/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_pkc_asymmetric_signature.c
 *
 * This file contains the implementation of the entry points associated to the
 * asymmetric signature capability as described by the PSA Cryptoprocessor
 * Driver interface specification
 *
 */
#include "mcux_psa_pkc_asymmetric_signature.h"
#include "mcux_psa_sgi_common_key_management.h"
#include "mcux_psa_pkc_key_generation.h"

#if defined(PSA_CRYPTO_DRIVER_PKC_PQC) && defined(PSA_WANT_ALG_ML_DSA)
#include "mcux_psa_pkc_pqc_utils.h"
#include <mcuxClMlDsa.h>

static psa_status_t pkc_pqc_ml_dsa_set_options(psa_algorithm_t alg,
                                               size_t bits,
                                               mcuxClMlDsa_Options_t *options)
{
    *options = 0u;

    if (PSA_ML_DSA_44_BITS == bits) {
        *options |= MCUXCLMLDSA_MODE_44;
    } else if (PSA_ML_DSA_65_BITS == bits) {
        *options |= MCUXCLMLDSA_MODE_65;
    } else if (PSA_ML_DSA_87_BITS == bits) {
        *options |= MCUXCLMLDSA_MODE_87;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* For now, we only support Hedged Pure ML-DSA */
    if (PSA_ALG_ML_DSA == alg) {
        *options |= MCUXCLMLDSA_MODE_PURE;
    } else if (PSA_ALG_DETERMINISTIC_ML_DSA == alg) {
        /* Not supported by CLib */
        return PSA_ERROR_NOT_SUPPORTED;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t pkc_pqc_ml_dsa_sign_message(const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg,
                                                const uint8_t *input,
                                                size_t input_length,
                                                uint8_t *signature,
                                                size_t signature_size,
                                                size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    uint32_t private_key_data[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA87_SK_LEN)];
    size_t private_key_length = 0u;
    uint32_t public_key_data[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA87_PK_LEN)];
    size_t public_key_length = 0u;
    uint32_t signature_length_local = 0u;

    mcuxClMlDsa_Options_t options = { 0 };
    mcuxClKey_Descriptor_t key_descriptor = { 0 };
    mcuxClSession_Descriptor_t session_descriptor = { 0 };
    mcuxClSession_Handle_t session = &session_descriptor;

    if (signature_size < PSA_MLDSA_SIGNATURE_SIZE(psa_get_key_bits(attributes))) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = pkc_pqc_ml_dsa_set_options(alg, psa_get_key_bits(attributes), &options);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Deterministically generate a keypair from the given seed */
    status = pkc_ml_dsa_generate_key_from_seed(attributes,
                                               key_buffer,
                                               key_buffer_size,
                                               (uint8_t *) private_key_data,
                                               sizeof(private_key_data),
                                               &private_key_length,
                                               (uint8_t *) public_key_data,
                                               sizeof(public_key_data),
                                               &public_key_length);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Create our signing key descriptor */
    status = sgi_create_key_descriptor(attributes,
                                       (uint8_t *) private_key_data,
                                       private_key_length,
                                       &key_descriptor);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Setup one session to be used by all functions called */
    MCUXCL_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                           MCUXCLMLDSA_MLDSA87_SIGN_SIZEOF_WA_CPU,
                                           0u, /* No PKC WA is used for signing */
                                           status, exit);

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCL_ALLOCATE_AND_INITIALIZE_RNG(session,
                                       MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
                                       mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3,
                                       status, exit);

    /* Create the signature mode */
    uint8_t signature_mode_bytes[MCUXCLSIGNATURE_MODE_SIZE] = { 0u };
    mcuxClSignature_ModeDescriptor_t *signature_mode =
        (mcuxClSignature_ModeDescriptor_t *) signature_mode_bytes;

    /* Create the protocol descriptor */
    uint8_t ml_dsa_protocol_descriptor_bytes[MCUXCLMLDSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE] = { 0u };
    mcuxClMlDsa_SignatureProtocolDescriptor_t *ml_dsa_protocol_descriptor =
        (mcuxClMlDsa_SignatureProtocolDescriptor_t *) ml_dsa_protocol_descriptor_bytes;

    /* Create the mode constructor */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_mode, token_mode,
                                     mcuxClMlDsa_SignatureModeConstructor(signature_mode,
                                                                          ml_dsa_protocol_descriptor,
                                                                          options,
                                                                          NULL,
                                                                          NULL,
                                                                          0U));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_SignatureModeConstructor) != token_mode) ||
        (MCUXCLSIGNATURE_STATUS_OK != result_mode)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUXCLBUFFER_INIT_RO(input_buf, NULL, input, input_length);
    MCUXCLBUFFER_INIT(signature_buf, NULL, signature, signature_size);

    /* Generate Signature */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_sign, token_sign,
                                     mcuxClSignature_sign(session,
                                                          (mcuxClKey_Handle_t) &key_descriptor,
                                                          signature_mode,
                                                          input_buf,
                                                          input_length,
                                                          signature_buf,
                                                          &signature_length_local));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != token_sign) ||
        (MCUXCLSIGNATURE_STATUS_OK != result_sign)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    *signature_length = (size_t) signature_length_local;
    status = PSA_SUCCESS;

exit:
    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        /* Don't override previous success/error, but if we were successful, report corruption */
        if (PSA_SUCCESS == status) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Clear the private key */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(clear_token,
                                            mcuxClMemory_clear((uint8_t *) private_key_data,
                                                                sizeof(private_key_data),
                                                                sizeof(private_key_data)));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) != clear_token) {
        /* Report corruption, as the private key may still be on the stack */
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    return status;
}

static psa_status_t pkc_pqc_ml_dsa_verify_message(const psa_key_attributes_t *attributes,
                                                  const uint8_t *key_buffer,
                                                  size_t key_buffer_size,
                                                  psa_algorithm_t alg,
                                                  const uint8_t *input,
                                                  size_t input_length,
                                                  const uint8_t *signature,
                                                  size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    uint32_t private_key_data[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA87_SK_LEN)];
    size_t private_key_length = 0u;
    uint32_t public_key_data[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA87_PK_LEN)];
    size_t public_key_length = 0u;

    const uint8_t *public_key_buf = NULL;

    mcuxClMlDsa_Options_t options = { 0 };
    mcuxClKey_Descriptor_t key_descriptor = { 0 };
    mcuxClSession_Descriptor_t session_descriptor = { 0 };
    mcuxClSession_Handle_t session = &session_descriptor;

    /* An upper bounds check. Otherwise we leave it to CLib to validate. */
    if (MCUXCLMLDSA_MLDSA87_SIG_LEN < signature_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    status = pkc_pqc_ml_dsa_set_options(alg, psa_get_key_bits(attributes), &options);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    if (PSA_KEY_TYPE_ML_DSA_KEY_PAIR == psa_get_key_type(attributes)) {
        public_key_buf = (uint8_t *)public_key_data;

        /* Deterministically generate a keypair from the given seed */
        status = pkc_ml_dsa_generate_key_from_seed(attributes,
                                                   key_buffer,
                                                   key_buffer_size,
                                                   (uint8_t *) private_key_data,
                                                   sizeof(private_key_data),
                                                   &private_key_length,
                                                   /* MISRA C-2012 Rule 11.8: Intentional to be able to
                                                    * use public_key_buf for both ML-DSA key types */
                                                   (uint8_t *) public_key_buf,
                                                   sizeof(public_key_data),
                                                   &public_key_length);
        if (PSA_SUCCESS != status) {
            goto exit;
        }
    } else if (PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY == psa_get_key_type(attributes)) {
        /* We receive the public key as-is, but we do check if the PK size matches */
        status = get_ml_key_sizes(attributes, &private_key_length, &public_key_length);
        if (PSA_SUCCESS != status) {
            goto exit;
        }
        if (key_buffer_size != public_key_length) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        public_key_buf = key_buffer;
        public_key_length = key_buffer_size;
    } else {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Create our verification key descriptor */
    status = sgi_create_key_descriptor(attributes,
                                       public_key_buf,
                                       public_key_length,
                                       &key_descriptor);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Setup one session to be used by all functions called */
    MCUXCL_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                           MCUXCLMLDSA_MLDSA87_WORKAREASIZE_MAX,
                                           MCUXCLMLDSA_VERIFY_SIZEOF_WA_PKC,
                                           status, exit);

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCL_ALLOCATE_AND_INITIALIZE_RNG(session,
                                       MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
                                       mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3,
                                       status, exit);

    /* Create the signature mode */
    uint8_t signature_mode_bytes[MCUXCLSIGNATURE_MODE_SIZE] = { 0u };
    mcuxClSignature_ModeDescriptor_t *signature_mode =
        (mcuxClSignature_ModeDescriptor_t *) signature_mode_bytes;

    /* Create the protocol descriptor */
    uint8_t ml_dsa_protocol_descriptor_bytes[MCUXCLMLDSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE] = { 0u };
    mcuxClMlDsa_SignatureProtocolDescriptor_t *ml_dsa_protocol_descriptor =
        (mcuxClMlDsa_SignatureProtocolDescriptor_t *) ml_dsa_protocol_descriptor_bytes;

    /* Create the mode constructor */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_mode, token_mode,
                                     mcuxClMlDsa_SignatureModeConstructor(signature_mode,
                                                                          ml_dsa_protocol_descriptor,
                                                                          options,
                                                                          NULL,
                                                                          NULL,
                                                                          0U));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_SignatureModeConstructor) != token_mode) ||
        (MCUXCLSIGNATURE_STATUS_OK != result_mode)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUXCLBUFFER_INIT_RO(input_buf, NULL, input, input_length);
    MCUXCLBUFFER_INIT_RO(signature_buf, NULL, signature, signature_length);

    /* Verify Signature */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_verify, token_verify,
                                     mcuxClSignature_verify(session,
                                                            (mcuxClKey_Handle_t) &key_descriptor,
                                                            signature_mode,
                                                            input_buf,
                                                            input_length,
                                                            signature_buf,
                                                            signature_length));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != token_verify) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
        goto exit;
    }
    if (MCUXCLSIGNATURE_STATUS_OK != result_verify) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    status = PSA_SUCCESS;

exit:
    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        /* Don't override previous success/error, but if we were successful, report corruption */
        if (PSA_SUCCESS == status) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Clear the private key */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(clear_token,
                                            mcuxClMemory_clear((uint8_t *) private_key_data,
                                                                sizeof(private_key_data),
                                                                sizeof(private_key_data)));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) != clear_token) {
        /* Report corruption, as the private key may still be on the stack */
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    return status;
}
#endif /* PSA_CRYPTO_DRIVER_PKC_PQC && PSA_WANT_ALG_ML_DSA */


psa_status_t pkc_verify_message(const psa_key_attributes_t *attributes,
                                const uint8_t *key_buffer,
                                size_t key_buffer_size,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                const uint8_t *signature,
                                size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if ((NULL == attributes) || (NULL == key_buffer) || (0u == key_buffer_size) ||
        (NULL == input) || (0u == input_length) ||
        (NULL == signature)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

#if defined(PSA_CRYPTO_DRIVER_PKC_PQC) && defined(PSA_WANT_ALG_ML_DSA)
    /* Enabling only Pure-MLDSA via this API for now */
    if (PSA_ALG_ML_DSA == alg) {
        status = pkc_pqc_ml_dsa_verify_message(attributes, key_buffer, key_buffer_size,
                                               alg, input, input_length, signature,
                                               signature_length);
    } else
#endif
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_unlock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t pkc_sign_message(const psa_key_attributes_t *attributes,
                              const uint8_t *key_buffer,
                              size_t key_buffer_size,
                              psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *signature,
                              size_t signature_size,
                              size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if ((NULL == attributes) || (NULL == key_buffer) || (0u == key_buffer_size) ||
        (NULL == input) || (0u == input_length) ||
        (NULL == signature) || (NULL == signature_length)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

#if defined(PSA_CRYPTO_DRIVER_PKC_PQC) && defined(PSA_WANT_ALG_ML_DSA)
    /* Enabling only Pure-MLDSA via this API for now */
    if (PSA_ALG_ML_DSA == alg) {
        status = pkc_pqc_ml_dsa_sign_message(attributes, key_buffer, key_buffer_size, alg,
                                            input, input_length, signature, signature_size,
                                            signature_length);
    } else
#endif
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_unlock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}



/******************************************************************************
 *                             PQC ADDON END                                  *
 *****************************************************************************/

/* Uncompressed public key = 0x04 tag byte + X and Y coordinates, each up to
 * MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP bytes (the largest supported prime field).
 * The pair buffer additionally holds the private scalar, whose length is also
 * bounded by MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP. Using the CL constant keeps
 * these buffers in sync with the raw point buffer used during export. */
#define MAX_PUB_KEY_SIZE_IN_BYTES  ((2u * MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP) + 1u)
#define MAX_PAIR_KEY_SIZE_IN_BYTES (MAX_PUB_KEY_SIZE_IN_BYTES + MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP)

psa_status_t pkc_sign_hash(const psa_key_attributes_t *attributes,
                           const uint8_t *key_buffer,
                           size_t key_buffer_size,
                           psa_algorithm_t alg, const uint8_t *input,
                           size_t input_length, uint8_t *signature,
                           size_t signature_size, size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t output_size = 0;
    uint32_t signatureSize = 0u;

    /* Validate all parameters BEFORE acquiring mutex */
    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == input || 0u == input_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == signature || NULL == signature_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Deterministic ECDSA not supported */
    if (true == PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Validate key type is ECC key pair */
    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_get_key_type(attributes))) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    output_size = PSA_SIGN_OUTPUT_SIZE(psa_get_key_type(attributes),
                                       psa_get_key_bits(attributes),
                                       alg);
    if (output_size > signature_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Acquire mutex */
    if (mcux_mutex_lock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc = { 0 };
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCL_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                           MCUXCLSIGNATURE_SIGN_ECDSA_WACPU_SIZE,
                                           MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_640,
                                           status, exit);

    /* Initialize the PRNG */
    MCUXCL_INITIALIZE_PRNG(session, status, exit);

    /* Create private key descriptor using the common key management utility */
    mcuxClKey_Descriptor_t privKeyDesc;
    status = sgi_create_key_descriptor(attributes, key_buffer, key_buffer_size, &privKeyDesc);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCL_ALLOCATE_AND_INITIALIZE_RNG(session,
                                       MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
                                       mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3,
                                       status, exit);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_status, ss_token, mcuxClSignature_sign(
                                         session,
                                         (mcuxClKey_Handle_t) &privKeyDesc,
                                         mcuxClSignature_Mode_ECDSA,
                                         input,
                                         input_length,
                                         signature,
                                         &signatureSize)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != ss_token) ||
        (MCUXCLSIGNATURE_STATUS_OK != ss_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    *signature_length = signatureSize;
    status = PSA_SUCCESS;

exit:
    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        /* Don't override previous success/error, but if we were successful, report corruption */
        if (PSA_SUCCESS == status) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t pkc_verify_hash(const psa_key_attributes_t *attributes,
                             const uint8_t *key_buffer,
                             size_t key_buffer_size,
                             psa_algorithm_t alg, const uint8_t *hash,
                             size_t hash_length, const uint8_t *signature,
                             size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (PSA_ALG_IS_ECDSA(alg) != true) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == hash || 0u == hash_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == signature || 0u == signature_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }


    if ((PSA_KEY_TYPE_IS_KEY_PAIR(psa_get_key_type(attributes)) != true)
        && (PSA_KEY_TYPE_IS_PUBLIC_KEY(psa_get_key_type(attributes)) != true)) {
        /* Invalid key type detected, The response shall be PSA_ERROR_NOT_SUPPORTED */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Acquire mutex */
    if (mcux_mutex_lock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc = { 0 };
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCL_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                           MCUXCLSIGNATURE_VERIFY_ECDSA_WACPU_SIZE,
                                           MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_640,
                                           status, exit);


    const uint8_t *key_data_pub = NULL;
    size_t key_data_size = 0u;

    /* For exporting the public part of the key */
    uint8_t public_key_data[MAX_PAIR_KEY_SIZE_IN_BYTES] = { 0u };
    size_t public_key_data_length = 0u;

    if (true == PSA_KEY_TYPE_IS_KEY_PAIR(psa_get_key_type(attributes))) {
        /* In PSA, an ECC key pair is represented by the secret value,
         * so we need to also export the public part and position them
         * correctly in memory [pub_x, pub_y, private] */
        status = pkc_internal_export_ecp_public_key(attributes,
                                                    key_buffer,
                                                    public_key_data,
                                                    MAX_PAIR_KEY_SIZE_IN_BYTES,
                                                    &public_key_data_length);

        if (PSA_SUCCESS != status) {
            goto exit;
        }

        if (0u == public_key_data_length) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }

        /* Need to move 1byte for leading byte (0x04) which is indicating uncompressed format. */
        key_data_pub = public_key_data + 1;
        key_data_size = public_key_data_length - 1u;
    } else if (true == PSA_KEY_TYPE_IS_PUBLIC_KEY(psa_get_key_type(attributes))) {

        /* Need to move 1byte for leading byte (0x04) which is indicating uncompressed format. */
        key_data_pub = (const uint8_t *) key_buffer + 1;
        key_data_size = key_buffer_size - 1u;
    } else {
        /* Expecting public key or keypair */
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Initialize the PRNG */
    MCUXCL_INITIALIZE_PRNG(session, status, exit);

    /* Create public key descriptor using the common key management utility.
     * Construct public-key attributes from the original attributes so that
     * sgi_create_key_descriptor resolves the correct public ECC type. */
    psa_key_attributes_t pub_attributes = *attributes;

    psa_key_type_t orig_type = psa_get_key_type(attributes);
    if (PSA_KEY_TYPE_IS_KEY_PAIR(orig_type)) {
        /* Convert key pair type to corresponding public key type */
        psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(orig_type);
        psa_set_key_type(&pub_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(family));
    }

    mcuxClKey_Descriptor_t pubKeyDesc;
    status = sgi_create_key_descriptor(&pub_attributes, key_data_pub, key_data_size, &pubKeyDesc);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCL_ALLOCATE_AND_INITIALIZE_RNG(session,
                                       MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
                                       mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3,
                                       status, exit);

    /**************************************************************************/
    /* ECDSA signature verification                                            */
    /**************************************************************************/
    /* Record critical parameters for additional protection */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rp_status, rp_token, mcuxClSignature_verify_recordParam(
                                         session,
                                         mcuxClSignature_Mode_ECDSA,
                                         hash,
                                         hash_length)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify_recordParam) != rp_token) ||
        (MCUXCLSIGNATURE_STATUS_OK != rp_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClSignature_verify(
                                         session,
                                         (mcuxClKey_Handle_t) &pubKeyDesc,
                                         mcuxClSignature_Mode_ECDSA,
                                         hash,
                                         hash_length,
                                         signature,
                                         signature_length)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != sv_token) ||
        (MCUXCLSIGNATURE_STATUS_OK != sv_status)) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    status = PSA_SUCCESS;

exit:
    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        /* Don't override previous success/error, but if we were successful, report corruption */
        if (PSA_SUCCESS == status) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&pkc_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}


/** @} */ // end of psa_asym_sign
