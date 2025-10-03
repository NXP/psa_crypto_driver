/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_sgi_cipher.c
 *
 * This file contains the implementation of the entry points associated to the
 * cipher capability (single-part only, multi-part (not supported in ele) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_sgi_init.h"
#include "mcux_psa_sgi_cipher.h"

/* To be able to include the PSA style configuration */
#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"

#include <mcuxClKey.h>
#include <mcuxClCipher.h>
#include <mcuxClCipherModes.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>

static inline uint8_t psa_cipher_to_sgi_alg(const psa_algorithm_t alg,
                                            const mcuxClCipher_ModeDescriptor_t **mode)
{
    uint8_t iv_required = 1u;
    switch (alg) {
#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            *mode = mcuxClCipher_Mode_AES_CBC_NoPadding;
            break;
#endif /* PSA_WANT_ALG_CBC_NO_PADDING */
#if defined(PSA_WANT_ALG_CTR)
        case PSA_ALG_CTR:
            *mode = mcuxClCipher_Mode_AES_CTR;
            break;
#endif /* PSA_WANT_ALG_CTR */
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            *mode       = mcuxClCipher_Mode_AES_ECB_NoPadding;
            iv_required = 0u;
            break;
#endif /* PSA_WANT_ALG_CTR */
        default:
            *mode = NULL;
            iv_required = 0u;
            break;
    }

    return iv_required;
}

psa_status_t sgi_transparent_cipher_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *iv,
                                            size_t iv_length,
                                            const uint8_t *input,
                                            size_t input_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits         = psa_get_key_bits(attributes);
    size_t key_bytes        = PSA_BITS_TO_BYTES(key_bits);

    /* Key buffer or size can't be NULL */
    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Key size should match the key_bits in attribute */
    if (key_buffer_size != key_bytes) {
        /* The attributes don't match the buffer given as input */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Algorithm needs to be a CIPHER algo */
    if (!PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((alg == PSA_ALG_ECB_NO_PADDING) && (input_length == 0)) {
        /* PSA specification is not very clear on 0 input for ECB.
         * However software implementation and the tests return SUCCESS
         * for 0 input. So adding this check here.
         */
        *output_length = 0;
        return PSA_SUCCESS;
    }

    /* If input length or input buffer NULL, it;s an error.
     * Special case for ECB where input = 0 may be allowed.
     * Taken care of in above code.
     */
    if (!input_length || !input) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Output buffer has to be atleast Input buffer size */
    if (output_size < input_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Output buffer can't be NULL */
    if (!output || !output_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* IV buffer can't be NULL or size different to 16 */
    if ((alg == PSA_ALG_CBC_NO_PADDING) || (alg == PSA_ALG_CTR)) {
        if (!iv || ((key_type == PSA_KEY_TYPE_AES) && (iv_length != PSA_CIPHER_IV_MAX_SIZE))) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    /* For CBC and ECB No padding, input length has to be multiple of cipher block length */
    if (((alg == PSA_ALG_CBC_NO_PADDING) || (alg == PSA_ALG_ECB_NO_PADDING)) &&
        (input_length % PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    ;

    mcuxClKey_Type_t type = { 0 };

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
            return PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                                  MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE,
                                                  0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session:        */ session,
                                         /* mcuxClKey_Handle_t key:                */ key,
                                         /* mcuxClKey_Type_t type:                 */ type,
                                         /* uint8_t * pKeyData:                   */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength:               */ key_buffer_size));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Initializing the output length with zero */
    uint32_t output_length_tmp = 0u;

    /* Variable for the AES mode. */
    const mcuxClCipher_ModeDescriptor_t *mode = NULL;
    psa_cipher_to_sgi_alg(alg, &mode);
    if (NULL == mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        e_status, e_token,
        mcuxClCipher_encrypt(
            /* mcuxClSession_Handle_t session:           */ session,
            /* const mcuxClKey_Handle_t key:             */ key,
            /* mcuxClCipher_Mode_t mode:                 */ mode,
            /* mcuxCl_InputBuffer_t pIv:                 */ iv,
            /* uint32_t ivLength:                       */ iv_length,
            /* mcuxCl_InputBuffer_t pIn:                 */ input,
            /* uint32_t inLength:                       */ input_length,
            /* mcuxCl_Buffer_t pOut:                     */ output,
            /* uint32_t * const outLength:              */ &output_length_tmp) /* only relevant in case of padding being
                                                                                  used */
        );
    *output_length = (size_t) output_length_tmp;

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_encrypt) != e_token) ||
        (MCUXCLCIPHER_STATUS_OK != e_status)) {
        return PSA_ERROR_GENERIC_ERROR;
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
        return PSA_ERROR_BAD_STATE;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_transparent_cipher_decrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits         = psa_get_key_bits(attributes);
    size_t key_bytes        = PSA_BITS_TO_BYTES(key_bits);

    uint32_t iv_length          = 0;
    uint32_t expected_op_length = 0;

    if (key_buffer_size != key_bytes) {
        /* The attributes don't match the buffer given as input */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((alg == PSA_ALG_ECB_NO_PADDING) && (input_length == 0)) {
        /* PSA specification is not very clear on 0 input for ECB.
         * However software implementation and the tests return SUCCESS
         * for 0 input. So adding this check here.
         */
        *output_length = 0;
        return PSA_SUCCESS;
    }

    /* If input length or input buffer NULL, it;s an error.
     * Special case for ECB where input = 0 may be allowed.
     * Taken care of in above code.
     */
    if (!input_length || !input) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Output buffer can't be NULL */
    if (!output || !output_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* IV buffer can't be NULL or size different to 16 */
    if ((alg == PSA_ALG_CBC_PKCS7) || (alg == PSA_ALG_CBC_NO_PADDING) || (alg == PSA_ALG_CTR)) {
        if (key_type == PSA_KEY_TYPE_AES) {
            iv_length = PSA_CIPHER_IV_MAX_SIZE;
        }
    }

    /* Input buffer -> IV + INPUT.
     * So output length would be (input - iv_length)
     */
    expected_op_length = input_length - iv_length;

    /* Input length has to be multiple of block size for decrypt operation */
    if ((alg == PSA_ALG_CBC_NO_PADDING || alg == PSA_ALG_CBC_PKCS7 ||
         alg == PSA_ALG_ECB_NO_PADDING) &&
        (expected_op_length % PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((alg != PSA_ALG_CBC_PKCS7) && (output_size < expected_op_length)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    mcuxClKey_Type_t type = { 0 };

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
            return PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;


    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                                  MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE,
                                                  0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session:        */ session,
                                         /* mcuxClKey_Handle_t key:                */ key,
                                         /* mcuxClKey_Type_t type:                 */ type,
                                         /* uint8_t * pKeyData:                   */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength:               */ key_buffer_size));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != prngInit_result)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Variable for the AES mode. Set this according to the key policy. */
    const mcuxClCipher_ModeDescriptor_t *mode = NULL;
    psa_cipher_to_sgi_alg(alg, &mode);
    if (NULL == mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }


    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(d_status, d_token, mcuxClCipher_decrypt(
                                         /* mcuxClSession_Handle_t session:           */ session,
                                         /* const mcuxClKey_Handle_t key:             */ key,
                                         /* mcuxClCipher_Mode_t mode:                 */ mode,
                                         /* mcuxCl_InputBuffer_t pIv:                 */ input,
                                         /* uint32_t ivLength:                       */ iv_length,
                                         /* mcuxCl_InputBuffer_t pIn:                 */ (
                                             mcuxCl_Buffer_t) (input + iv_length),
                                         /* uint32_t inLength:                       */ input_length
                                         - iv_length,
                                         /* mcuxCl_Buffer_t pOut:                     */ output,
                                         /* uint32_t * const outLength:              */ &
                                         expected_op_length)
                                     );

    *output_length = (size_t) expected_op_length;

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_decrypt) != d_token) ||
        (MCUXCLCIPHER_STATUS_OK != d_status)) {
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
        return PSA_ERROR_BAD_STATE;
    }

    /* Return with success */
    return PSA_SUCCESS;


}
