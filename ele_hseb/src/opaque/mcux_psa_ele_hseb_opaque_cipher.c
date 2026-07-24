/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_ele_hseb_opaque_cipher.c
 *
 * This file contains the implementation of the entry points associated to the
 * cipher capability as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "ele_hseb_crypto_primitives.h"
#include "mcux_psa_ele_hseb_opaque_cipher.h"
#include "mcux_psa_ele_hseb_utils.h"
#include "mcux_psa_ele_hseb_common_init.h"
#include "mcux_psa_ele_hseb_common_cipher.h"
#include "mcux_psa_ele_hseb_translate.h"

#define AES_BLOCK_LENGTH (16u)

psa_status_t ele_hseb_opaque_cipher_encrypt(const psa_key_attributes_t *attributes,
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
    psa_status_t status              = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status     = HSE_SRV_RSP_GENERAL_ERROR;
    psa_key_type_t key_type          = psa_get_key_type(attributes);
    hseKeyHandle_t aes_key_handle    = 0u;
    hseCipherBlockMode_t cipher_mode = HSE_CIPHER_BLOCK_MODE_NULL;

    if (NULL == key_buffer || 0u == key_buffer_size ||
        NULL == output     || NULL == output_length ||
        NULL == input) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_AES != key_type) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Algorithm must be a CIPHER algorithm */
    if (false == PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Translate mode from PSA to HSE */
    cipher_mode = psa_to_hseb_cipher_mode(alg);

    if (HSE_CIPHER_BLOCK_MODE_NULL == cipher_mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Check IV length for all modes except ECB */
    if ((PSA_ALG_ECB_NO_PADDING != alg) &&
        (PSA_CIPHER_IV_LENGTH(key_type, alg) != iv_length)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (false == ele_hseb_is_cipher_input_length_correct(input_length, alg, key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check output buffer size */
    if (output_size < input_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* For opaque keys the handle is stored in the key buffer */
    if (sizeof(hseKeyHandle_t) != key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ele_hseb_read_key_handle_from_buffer(key_buffer, &aes_key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Do the encryption */
    hseb_status = AesCrypt(aes_key_handle, cipher_mode, HSE_CIPHER_DIR_ENCRYPT,
                           iv, input_length, input, output);
    if (HSE_SRV_RSP_OK != hseb_status) {
        status = ele_hseb_to_psa_status(hseb_status);
        goto exit;
    }

    /* Only those algorithms are supported,
     * for which input and output lengths are equal
     */
    *output_length = input_length;

    status = PSA_SUCCESS;

exit:
    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_decrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{
    psa_status_t status              = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status     = HSE_SRV_RSP_GENERAL_ERROR;
    psa_key_type_t key_type          = psa_get_key_type(attributes);
    hseKeyHandle_t aes_key_handle    = 0u;
    hseCipherBlockMode_t cipher_mode = HSE_CIPHER_BLOCK_MODE_NULL;
    size_t iv_length                 = PSA_CIPHER_IV_LENGTH(key_type, alg);
    const uint8_t *iv                = input;
    const uint8_t *input_no_iv       = NULL;
    size_t input_no_iv_length        = 0u;

    if (NULL == key_buffer || 0u == key_buffer_size ||
        NULL == output     || NULL == output_length ||
        NULL == input) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_AES != key_type) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Algorithm must be a CIPHER algorithm */
    if (false == PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* If alg takes IV, then it must by equal to AES_BLOCK_LENGTH */
    if (PSA_ALG_ECB_NO_PADDING != alg &&
        AES_BLOCK_LENGTH != iv_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Validate that input_length is large enough to subtract iv_length */
    if (input_length < iv_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Now safe to compute payload pointer and length */
    input_no_iv       = input + iv_length;
    input_no_iv_length = input_length - iv_length;

    /* Translate mode from PSA to HSE */
    cipher_mode = psa_to_hseb_cipher_mode(alg);

    if (HSE_CIPHER_BLOCK_MODE_NULL == cipher_mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (false == ele_hseb_is_cipher_input_length_correct(input_no_iv_length, alg, key_type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check output buffer size */
    if (output_size < PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_no_iv_length)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* For opaque keys the handle is stored in the key buffer */
    if (sizeof(hseKeyHandle_t) != key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ele_hseb_read_key_handle_from_buffer(key_buffer, &aes_key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Do the decryption */
    hseb_status = AesCrypt(aes_key_handle, cipher_mode, HSE_CIPHER_DIR_DECRYPT,
                           iv, input_no_iv_length, input_no_iv, output);
    if (HSE_SRV_RSP_OK != hseb_status) {
        status = ele_hseb_to_psa_status(hseb_status);
        goto exit;
    }

    *output_length = PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_no_iv_length);

    status = PSA_SUCCESS;

exit:
    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_encrypt_setup(
    ele_hseb_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    hseKeyHandle_t key_handle = 0u;

    /* For opaque keys the handle is stored in the key buffer */
    if (sizeof(hseKeyHandle_t) != key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ele_hseb_read_key_handle_from_buffer(key_buffer, &key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    status = ele_hseb_common_cipher_setup(key_handle, operation, attributes, key_buffer,
                                          key_buffer_size, alg, HSE_CIPHER_DIR_ENCRYPT);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_decrypt_setup(
    ele_hseb_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    hseKeyHandle_t key_handle = 0u;

    /* For opaque keys the handle is stored in the key buffer */
    if (sizeof(hseKeyHandle_t) != key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ele_hseb_read_key_handle_from_buffer(key_buffer, &key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    status = ele_hseb_common_cipher_setup(key_handle, operation, attributes, key_buffer,
                                          key_buffer_size, alg, HSE_CIPHER_DIR_DECRYPT);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_set_iv(ele_hseb_opaque_cipher_operation_t *operation,
                                           const uint8_t *iv,
                                           size_t iv_length)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    hseKeyHandle_t key_handle = 0u;

    /* If alg takes IV, then it must by equal to AES_BLOCK_LENGTH */
    if (HSE_CIPHER_BLOCK_MODE_ECB != operation->cipher_mode &&
        AES_BLOCK_LENGTH != iv_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ele_hseb_read_key_handle_from_buffer(operation->key, &key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* This is where we actually start the streaming operation, since PSA just
     * now provided the IV, which is required by the HSEB START request.
     *
     * Not applicable to ECB, since it takes no IV. ECB was started during setup
     * call.
     */
    status = ele_hseb_common_cipher_start_stream_internal(operation, key_handle, iv);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_update(ele_hseb_opaque_cipher_operation_t *operation,
                                           const uint8_t *input,
                                           size_t input_length,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    hseKeyHandle_t key_handle = 0u;

    ele_hseb_read_key_handle_from_buffer(operation->key, &key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    status = ele_hseb_common_cipher_update(key_handle, operation, input, input_length,
                                           output, output_size, output_length);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_finish(ele_hseb_opaque_cipher_operation_t *operation,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{
    psa_status_t status          = PSA_ERROR_CORRUPTION_DETECTED;
    hseKeyHandle_t key_handle    = 0u;

    ele_hseb_read_key_handle_from_buffer(operation->key, &key_handle);

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    status = ele_hseb_common_cipher_finish(key_handle, operation,
                                           output, output_size, output_length);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_cipher_abort(ele_hseb_opaque_cipher_operation_t *operation)
{
    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Call FINISH with bad inputs to invalidate the HSEB streaming operation.
     * Possibly not needed.
     */
    (void) AesFinishStreamEncrypt(0u,
                                  HSE_CIPHER_BLOCK_MODE_NULL,
                                  0u,
                                  NULL,
                                  NULL,
                                  HSE_SGT_OPTION_NONE);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Zeroize the context */
    (void) memset(operation, 0, sizeof(ele_hseb_opaque_cipher_operation_t));

    return PSA_SUCCESS;
}
