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
#include <internal/mcuxClCipherModes_Sgi_Types.h>

#include <mcuxClMemory_Clear.h>

static inline void psa_cipher_to_sgi_alg(const psa_algorithm_t alg,
                                         const mcuxClCipher_ModeDescriptor_t **mode)
{
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
#if defined(PSA_WANT_ALG_CBC_PKCS7)
        case PSA_ALG_CBC_PKCS7:
            *mode = mcuxClCipher_Mode_AES_CBC_PaddingPKCS7;
            break;
#endif /* PSA_WANT_ALG_CBC_PKCS7 */
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            *mode       = mcuxClCipher_Mode_AES_ECB_NoPadding;
            break;
#endif /* PSA_WANT_ALG_ECB_NO_PADDING */
        default:
            *mode = NULL;
            break;
    }

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
        return PSA_ERROR_SERVICE_FAILURE;
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
        return PSA_ERROR_SERVICE_FAILURE;
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
        return PSA_ERROR_SERVICE_FAILURE;
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

    /* Variable for the AES mode. */
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

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_decrypt) != d_token)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

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

    if (MCUXCLCIPHER_STATUS_OK == d_status) {
        return PSA_SUCCESS;
    } else if (MCUXCLPADDING_STATUS_ERROR == d_status) {
        return PSA_ERROR_INVALID_PADDING;
    } else {
        return PSA_ERROR_GENERIC_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();


}

static psa_status_t cipher_common_setup(sgi_cipher_operation_t *operation,
                                        const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        psa_encrypt_or_decrypt_t cipher_direction)
{

    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits         = psa_get_key_bits(attributes);


    /* Here we only set up the internal cipher driver context.
     * Actual init of operation will happen in sgi_transparent_cipher_set_iv().
     */

    if (PSA_KEY_TYPE_AES != key_type) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (32u < key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Variable for the AES mode. */
    psa_cipher_to_sgi_alg(alg, &operation->mode);
    if (NULL == operation->mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->cipher_direction = cipher_direction;

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                                  MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE,
                                                  0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

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

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status,
                                     ki_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session:        */ session,
                                         /* mcuxClKey_Handle_t key:                */ (
                                             mcuxClKey_Handle_t) &operation->keyDesc,
                                         /* mcuxClKey_Type_t type:                 */ type,
                                         /* uint8_t * pKeyData:                   */ (uint8_t *)
                                         key_buffer,
                                         /* uint32_t keyDataLength:               */ key_buffer_size)
                                     );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) ||
        (MCUXCLKEY_STATUS_OK != ki_status)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
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

psa_status_t sgi_transparent_cipher_encrypt_setup(
    sgi_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return cipher_common_setup(operation, attributes, key_buffer,
                               key_buffer_size, alg, PSA_CRYPTO_DRIVER_ENCRYPT);
}

psa_status_t sgi_transparent_cipher_decrypt_setup(
    sgi_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return cipher_common_setup(operation, attributes, key_buffer,
                               key_buffer_size, alg, PSA_CRYPTO_DRIVER_DECRYPT);

}

psa_status_t sgi_transparent_cipher_set_iv(sgi_cipher_operation_t *operation,
                                           const uint8_t *iv,
                                           size_t iv_length)
{

    /* If alg takes IV, then it must by equal to MCUXCLAES_BLOCK_SIZE */
    if (mcuxClCipher_Mode_AES_ECB_NoPadding != operation->mode &&
        MCUXCLAES_BLOCK_SIZE != iv_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                                  MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE,
                                                  0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


    mcuxClCipher_Context_t * const ctx = (mcuxClCipher_Context_t *) operation->ctx;

    mcuxClKey_Handle_t const key = (mcuxClKey_Handle_t) &operation->keyDesc;


    if (PSA_CRYPTO_DRIVER_ENCRYPT == operation->cipher_direction) {

        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ei_status, ei_token, mcuxClCipher_init_encrypt(
                                             /* mcuxClSession_Handle_t session:         */ session,
                                             /* mcuxClCipher_Context_t * const pContext:*/ ctx,
                                             /* const mcuxClKey_Handle_t key:           */ key,
                                             /* mcuxClCipher_Mode_t mode:               */ operation
                                             ->mode,
                                             /* mcuxCl_InputBuffer_t pIv:               */ iv,
                                             /* uint32_t ivLength:                     */ iv_length)
                                         );

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init_encrypt) != ei_token) ||
            (MCUXCLCIPHER_STATUS_OK != ei_status)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_END();

    } else { /* PSA_CRYPTO_DRIVER_DECRYPT */

        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(di_status, di_token, mcuxClCipher_init_decrypt(
                                             /* mcuxClSession_Handle_t session:         */ session,
                                             /* mcuxClCipher_Context_t * const pContext:*/ ctx,
                                             /* const mcuxClKey_Handle_t key:           */ key,
                                             /* mcuxClCipher_Mode_t mode:               */ operation
                                             ->mode,
                                             /* mcuxCl_InputBuffer_t pIv:               */ iv,
                                             /* uint32_t ivLength:                     */ iv_length)
                                         );

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init_decrypt) != di_token) ||
            (MCUXCLCIPHER_STATUS_OK != di_status)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_END();


    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
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
psa_status_t sgi_transparent_cipher_update(sgi_cipher_operation_t *operation,
                                           const uint8_t *input,
                                           size_t input_length,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{

    size_t expected_output_size;

    expected_output_size = output_size == 0u ? output_size : input_length;

    /* Potential check for small output buffer size*/
    if (output_size < expected_output_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                                  MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE,
                                                  0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    mcuxClCipher_Context_t * const ctx = (mcuxClCipher_Context_t *) operation->ctx;

    uint32_t output_length_tmp = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep1_status, ep1_token, mcuxClCipher_process(
                                         /* mcuxClSession_Handle_t session:         */ session,
                                         MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED(
                                             "Initialized by mcuxClCipher_init_encrypt")
                                         /* mcuxClCipher_Context_t * const pContext:*/ ctx,
                                         MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
                                         /* mcuxCl_InputBuffer_t pIn:               */ input,
                                         /* uint32_t inLength:                     */ input_length,
                                         /* mcuxCl_Buffer_t pOut:                   */ output,
                                         /* uint32_t * const outLength:            */ &
                                         output_length_tmp)
                                     );

    *output_length = (size_t) output_length_tmp;

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != ep1_token) ||
        (MCUXCLCIPHER_STATUS_OK != ep1_status)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
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

psa_status_t sgi_transparent_cipher_finish(sgi_cipher_operation_t *operation,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* check for invalid input based upon following rule
       inLength needs to be a multiple of the granularity, if this is not the case, return an error. */
    mcuxClCipher_Context_t * const ctx = (mcuxClCipher_Context_t *) operation->ctx;

    mcuxClCipherModes_Context_Aes_Sgi_t * const pCtx = (mcuxClCipherModes_Context_Aes_Sgi_t *) ctx;;
    mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo =
        (mcuxClCipherModes_Algorithm_Aes_Sgi_t) (pCtx->common.pMode->pAlgorithm);

    /* Return INVALID_INPUT if totalInputLength doesn't meet the required granularity */
    if (0u != (pCtx->common.totalInputLength % pAlgo->granularityEnc)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0u != (pCtx->common.totalInputLength > output_size)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                                  MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE,
                                                  0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    uint32_t output_length_tmp = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(df_status, df_token, mcuxClCipher_finish(
                                         /* mcuxClSession_Handle_t session:         */ session,
                                         MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED(
                                             "Initialized by mcuxClCipher_init_en/decrypt")
                                         /* mcuxClCipher_Context_t * const pContext:*/ ctx,
                                         MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
                                         /* mcuxCl_Buffer_t pOut:                   */ output,
                                         /* uint32_t * const outLength:            */ &
                                         output_length_tmp)
                                     );


    *output_length = (size_t) output_length_tmp;

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != df_token) ||
        (MCUXCLCIPHER_STATUS_OK != df_status)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
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

psa_status_t sgi_transparent_cipher_abort(sgi_cipher_operation_t *operation)
{
    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Clear cipher ctx */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(token, mcuxClMemory_clear((uint8_t *) operation,
                                                                    sizeof(sgi_cipher_operation_t),
                                                                    sizeof(sgi_cipher_operation_t)));


    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) != token) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}
