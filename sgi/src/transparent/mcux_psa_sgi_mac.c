/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_sgi_mac.c
 *
 * This file contains the implementation of the entry points associated to the
 * mac capability (single-part and multipart) as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_sgi_mac.h"


#include <mcuxClHmac.h>
#include <mcuxClMacModes.h>


#include <internal/mcuxClMacModes_Sgi_Types.h>

/*
 * Entry points for MAC computation and verification as described by the PSA
 *  Cryptoprocessor Driver interface specification
 */

typedef struct {
    mcuxClMac_Context_t macctx;
    mcuxClKey_Descriptor_t keydesc;
    psa_algorithm_t alg;
} psa_mac_data_t;


/* Convert PSA Algorithm to ELE Algorithm, CMAC or HMAC with SHA256 */
static inline mcuxClMac_Mode_t   get_mac_sgi_mode(const psa_key_attributes_t *attributes,
                                                  psa_algorithm_t alg)
{
    if (psa_get_key_type(attributes) == PSA_KEY_TYPE_AES) {
        MCUX_CSSL_ANALYSIS_START_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()
        switch (PSA_ALG_FULL_LENGTH_MAC(alg)) {
            //AES based algorithms and paddings
            case PSA_ALG_CMAC:
                /* Special case added, where CMAC with key size 192 bits is not supported by ELS, check added to do SW fallback. */
                if (192u == psa_get_key_bits(attributes)) {
                    return NULL;
                }
                return mcuxClMac_Mode_CMAC;
            default:
                return NULL;
        }
        MCUX_CSSL_ANALYSIS_STOP_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()
    } else {
        return NULL;
    }
}

psa_status_t sgi_mac_compute(const psa_key_attributes_t *attributes,
                             const uint8_t *key_buffer,
                             size_t key_buffer_size,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length)
{
    size_t key_bits          = psa_get_key_bits(attributes);
    psa_key_type_t key_type  = psa_get_key_type(attributes);

    /* Get the correct MAC mode based on the given algorithm. */
    const mcuxClMac_ModeDescriptor_t *mode;
    mode = get_mac_sgi_mode(attributes, alg);
    if (mode == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    mac_size = PSA_MAC_LENGTH(key_type, key_bits, alg);

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE, 0u);


    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;
    mcuxClKey_Type_t type = { 0 };

    if (psa_get_key_type(attributes) == PSA_KEY_TYPE_AES &&
        (psa_get_key_bits(attributes) == 128 ||
         psa_get_key_bits(attributes) == 256)) {
        switch (key_bits) {
#if defined(PSA_WANT_KEY_TYPE_AES)
            case 128:
                type = mcuxClKey_Type_Aes128;
                break;
            case 256:
                type = mcuxClKey_Type_Aes256;
                break;
#endif /* PSA_WANT_KEY_TYPE_AES */
            default:
                type = NULL;
                break;
        }
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ session,
                                         /* mcuxClKey_Handle_t key                 */ key,
                                         /* mcuxClKey_Type_t type                  */ type,
                                         /* uint8_t * pKeyData                    */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength                */ key_buffer_size)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t mac_length_tmp = mac_size;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mc_status, mc_token, mcuxClMac_compute(
                                         /* mcuxClSession_Handle_t session:  */ session,
                                         /* const mcuxClKey_Handle_t key:    */ key,
                                         /* const mcuxClMac_Mode_t mode:     */ mode,
                                         /* mcuxCl_InputBuffer_t pIn:        */ input,
                                         /* uint32_t inLength:              */ input_length,
                                         /* mcuxCl_Buffer_t pMac:            */ mac,
                                         /* uint32_t * const pMacLength:    */ &mac_length_tmp)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_compute) != mc_token) ||
        (MCUXCLMAC_STATUS_OK != mc_status)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    *mac_length = mac_length_tmp;

    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_mac_sign_setup(sgi_mac_operation_t *operation,
                                const psa_key_attributes_t *attributes,
                                const uint8_t *key_buffer,
                                size_t key_buffer_size, psa_algorithm_t alg)
{

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_mac_data_t *ctx = (psa_mac_data_t *) operation->ctx;

    /* Set alg in clns_data for update and finalize */
    ctx->alg = alg;

    /* Get the correct MAC mode based on the given algorithm. */
    const mcuxClMac_ModeDescriptor_t *mode;
    mode = get_mac_sgi_mode(attributes, ctx->alg);
    if (mode == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* No support for multipart Hmac */
    if (PSA_ALG_IS_HMAC(alg) == true) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


    mcuxClKey_Descriptor_t *keyDesc = &ctx->keydesc;
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ session,
                                         /* mcuxClKey_Handle_t key                 */ key,
                                         /* mcuxClKey_Type_t type                  */
                                         mcuxClKey_Type_Aes128,
                                         /* uint8_t * pKeyData                    */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength                */ key_buffer_size));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mi_status, mi_token, mcuxClMac_init(
                                         /* mcuxClSession_Handle_t session:       */ session,
                                         /* mcuxClMac_Context_t * const pContext: */ &ctx->macctx,
                                         /* const mcuxClKey_Handle_t key:         */ key,
                                         /* mcuxClMac_Mode_t mode:                */ mode)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_init) != mi_token) ||
        (MCUXCLMAC_STATUS_OK != mi_status)) {
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
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}
/** @} */ // end of psa_mac
