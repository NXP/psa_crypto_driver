/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_sgi_aead.c
 *
 * This file contains the implementations of the entry points associated to the
 * aead capability (single-part and multipart) as described by the PSA
 * Cryptoprocessor Driver interface specification.
 *
 */

#include "mcux_psa_sgi_init.h"
#include "mcux_psa_sgi_aead.h"

/* To be able to include the PSA style configuration */
#include "mbedtls/build_info.h"

#include <mcuxClAead.h>
#include <mcuxClAeadModes.h>

static inline psa_status_t check_tag_length(const psa_algorithm_t alg)
{
    uint32_t tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    /* Recover default algorithm (could be CCM with changed tag size) */
    const psa_algorithm_t algDefault = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);

    psa_status_t status = PSA_SUCCESS;

    switch (algDefault) {
        case PSA_ALG_CCM:
            /* Add checks for valid CCM tag length, otherwise return error*/
            if ((tag_length < 4u) || (tag_length > 16u) || (tag_length % 2u != 0u)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;

        case PSA_ALG_GCM:
            /* Add checks for valid GCM tag length, otherwise return error*/
            if ((4u != tag_length) && (8u != tag_length) &&
                ((tag_length < 12u) || (tag_length > 16u))) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;

        default:
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
    }

    return status;
}

static inline mcuxClAead_Mode_t  get_aead_sgi_mode(psa_algorithm_t alg)
{
    psa_algorithm_t default_alg = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);

    const mcuxClAead_ModeDescriptor_t *mode = NULL;

    switch (default_alg) {
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_CCM:
            mode             = mcuxClAead_Mode_CCM;
            break;
#endif /* PSA_WANT_ALG_CCM */
#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_GCM:
            mode             = mcuxClAead_Mode_GCM;
            break;
#endif /* PSA_WANT_ALG_GCM */
        default:
            return NULL;
    }

    return (mcuxClAead_Mode_t) mode;
}

/** \defgroup psa_aead PSA driver entry points for AEAD
 *
 *  Entry points for AEAD encryption and decryption as described by the PSA
 *  Cryptoprocessor Driver interface specification
 *
 *  @{
 */
psa_status_t sgi_aead_encrypt(const psa_key_attributes_t *attributes,
                              const uint8_t *key_buffer,
                              size_t key_buffer_size,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *plaintext,
                              size_t plaintext_length,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length)
{
    psa_key_type_t key_type  = psa_get_key_type(attributes);
    size_t key_bits          = psa_get_key_bits(attributes);
    size_t tag_length        = 0;

    uint8_t *tag             = NULL;

    /* Algorithm needs to be a AEAD algo */
    if (!PSA_ALG_IS_AEAD(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Only AES key type is supported, check for that */
    if (key_type != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Validate tag length */
    if (check_tag_length(alg) != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Get the correct AEAD mode based on the given algorithm. */
    mcuxClAead_Mode_t mode = get_aead_sgi_mode(alg);
    if (NULL == mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Get the TAG length encoded in the algorithm */
    tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    /* Key buffer or size can't be NULL */
    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Key size should match the key_bits in attribute */
    if (PSA_BYTES_TO_BITS(key_buffer_size) != key_bits) {
        /* The attributes don't match the buffer given as input */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Nonce can't be NULL */
    if (NULL == nonce || 0u == nonce_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* No check for input and additional data as 0 value for these is allowed */

    /* Output buffer has to be atleast Input buffer size  -> Check for encrypt */
    if (ciphertext_size < (plaintext_length + tag_length)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Output buffer can't be NULL */
    if (NULL == ciphertext || NULL == ciphertext_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLAEAD_WA_SIZE_MAX, 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ session,
                                         /* mcuxClKey_Handle_t key                 */ key,
                                         /* mcuxClKey_Type_t type                  */
                                         mcuxClKey_Type_Aes128,
                                         /* uint8_t * pKeyData                    */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength                */ key_buffer_size)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t ciphertext_length_tmp = 0u;

    tag    = (uint8_t *) (ciphertext + plaintext_length);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(e_status, e_token, mcuxClAead_encrypt(
                                         /* mcuxClSession_Handle_t session:        */ session,
                                         /* const mcuxClKey_Handle_t key:          */ key,
                                         /* const mcuxClAead_Mode_t * const mode:  */ mode,
                                         /* mcuxCl_InputBuffer_t nonce             */ nonce,
                                         /* uint32_t nonceSize,                   */ nonce_length,
                                         /* mcuxCl_InputBuffer_t in                */ plaintext,
                                         /* uint32_t inSize,                      */
                                         plaintext_length,
                                         /* mcuxCl_InputBuffer_t adata             */
                                         additional_data,
                                         /* uint32_t adataSize,                   */
                                         additional_data_length,
                                         /* mcuxCl_Buffer_t out,                   */ ciphertext,
                                         /* uint32_t * const outSize              */ &
                                         ciphertext_length_tmp,
                                         /* mcuxCl_Buffer_t tag,                   */ tag,
                                         /* const uint32_t tagSize,               */ tag_length)
                                     );


    *ciphertext_length = (size_t) ciphertext_length_tmp;

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_encrypt) != e_token) ||
        (MCUXCLAEAD_STATUS_OK != e_status)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Update ciphertext_length by tag size, as they are in the same buffer */
    *ciphertext_length += tag_length;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf_status, kf_token, mcuxClKey_flush(
                                         /* mcuxClSession_Handle_t session:      */ session,
                                         /* mcuxClKey_Handle_t key:              */ key)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != kf_token) ||
        (MCUXCLKEY_STATUS_OK != kf_status)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();
    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_aead_decrypt(const psa_key_attributes_t *attributes,
                              const uint8_t *key_buffer,
                              size_t key_buffer_size,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *ciphertext,
                              size_t ciphertext_length,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length)
{
    psa_key_type_t key_type  = psa_get_key_type(attributes);
    size_t key_bits          = psa_get_key_bits(attributes);
    size_t tag_length        = 0;
    size_t cipher_length     = 0;

    /* Algorithm needs to be a AEAD algo */
    if (!PSA_ALG_IS_AEAD(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Only AES key type is supported, first check for that */
    if (key_type != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Validate given sizes */
    uint32_t needed_output_size = PSA_AEAD_DECRYPT_OUTPUT_SIZE(psa_get_key_type(attributes),
                                                               alg,
                                                               ciphertext_length);
    if (plaintext_size < needed_output_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Validate tag length */
    if (check_tag_length(alg) != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Get the correct AEAD mode based on the given algorithm. */
    mcuxClAead_Mode_t mode = get_aead_sgi_mode(alg);
    if (NULL == mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Get the correct tag length based on the given algorithm, and validate the given ciphertext_length (that contains the tag_length) */
    tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
    if (ciphertext_length < tag_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Key buffer or size can't be NULL */
    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Key size should match the key_bits in attribute */
    if (PSA_BYTES_TO_BITS(key_buffer_size) != key_bits) {
        /* The attributes don't match the buffer given as input */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Input Buffer or size can't be NULL */
    if (NULL == ciphertext || 0u == ciphertext_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == nonce || 0u == nonce_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Output buffer has to be atleast Input buffer size  -> Check for encrypt */

    if (plaintext_size < cipher_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Input buffer i.e plaintext or AAD is allowed to be 0 in encrypt
     * Operation. Hence output of a decrypt can be of size 0. Hence no
     * check involving plaintext buffer.
     */

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLAEAD_WA_SIZE_MAX, 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ session,
                                         /* mcuxClKey_Handle_t key                 */ key,
                                         /* mcuxClKey_Type_t type                  */
                                         mcuxClKey_Type_Aes128,
                                         /* uint8_t * pKeyData                    */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength                */ key_buffer_size)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* RUN AEAD */

    uint32_t plaintext_length_tmp = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(d_status, d_token, mcuxClAead_decrypt(
                                         /* mcuxClSession_Handle_t session:       */ session,
                                         /* const mcuxClKey_Handle_t key:         */ key,
                                         /* const mcuxClAead_Mode_t * const mode: */ mode,
                                         /* mcuxCl_InputBuffer_t nonce,           */ nonce,
                                         /* const uint32_t nonceSize,             */ nonce_length,
                                         /* mcuxCl_InputBuffer_t in               */ ciphertext,
                                         /* uint32_t inSize,                      */
                                         ciphertext_length - tag_length,
                                         /* mcuxCl_InputBuffer_t adata            */ additional_data,
                                         /* const uint32_t adataSize,             */
                                         additional_data_length,
                                         /* mcuxCl_Buffer_t tag,                  */ (uint8_t *) &
                                         ciphertext[ciphertext_length - tag_length],
                                         /* const uint32_t tagSize,               */ tag_length,
                                         /* mcuxCl_Buffer_t out,                  */ plaintext,
                                         /* uint32_t * const outSize              */ &
                                         plaintext_length_tmp));

    *plaintext_length = (size_t) plaintext_length_tmp;

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_decrypt) != d_token)) {
        return PSA_ERROR_GENERIC_ERROR;
    }



    /**************************************************************************/
    /* Key Flush                                                              */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf_status, kf_token, mcuxClKey_flush(
                                         /* mcuxClSession_Handle_t session:      */ session,
                                         /* mcuxClKey_Handle_t key:              */ key)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != kf_token) ||
        (MCUXCLKEY_STATUS_OK != kf_status)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();



    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (MCUXCLAEAD_STATUS_OK == d_status) {
        return PSA_SUCCESS;
    } else if (MCUXCLAEAD_STATUS_INVALID_TAG == d_status) {
        return PSA_ERROR_INVALID_SIGNATURE;
    } else {
        return PSA_ERROR_GENERIC_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

}

/** @} */ // end of psa_aead
