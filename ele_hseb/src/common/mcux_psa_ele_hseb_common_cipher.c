/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_ele_hseb_common_cipher.c
 *
 * This file contains common definitions used by the transparent and opaque
 * cipher drivers.
 *
 */

#include "ele_hseb_crypto_primitives.h"
#include "mcux_psa_ele_hseb_utils.h"
#include "mcux_psa_ele_hseb_common_init.h"
#include "mcux_psa_ele_hseb_common_cipher.h"
#include "mcux_psa_ele_hseb_translate.h"

#include "mcux_psa_util_wrapcheck_static_inline.h"

#include "hse_host_cipher.h"

#define AES_BLOCK_LENGTH (16u)

bool ele_hseb_is_cipher_input_length_correct(size_t input_length,
                                             psa_algorithm_t alg,
                                             psa_key_type_t key_type)
{
    const size_t cipher_block_length = PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type);

    /* Prevent undefined behavior on division by zero by exiting early */
    if (0u == cipher_block_length) {
        return false;
    }

    /* The *_NO_PADDING and CFB modes require input length to be a multiple of block size */
    if (((PSA_ALG_ECB_NO_PADDING == alg) ||
         (PSA_ALG_CBC_NO_PADDING == alg) ||
         (PSA_ALG_CFB == alg)) &&
        (0u != (input_length % cipher_block_length))) {
        return false;
    }
    return true;
}

bool ele_hseb_is_cipher_key_bit_size_valid(size_t key_bits)
{
    if ((128u == key_bits) || (192u == key_bits) || (256u == key_bits)) {
        return true;
    }
    return false;
}

static psa_status_t cipher_update_compute(hseKeyHandle_t key_handle,
                                          hseCipherBlockMode_t cipher_mode,
                                          uint32_t input_length,
                                          const uint8_t *input,
                                          uint8_t *output,
                                          hseCipherDir_t cipher_direction)
{
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;

    if (HSE_CIPHER_DIR_ENCRYPT == cipher_direction) {
        hseb_status = AesUpdateStreamEncrypt(key_handle,
                                             cipher_mode,
                                             input_length,
                                             input,
                                             output,
                                             HSE_SGT_OPTION_NONE);
    } else { /* HSE_CIPHER_DIR_DECRYPT */
        hseb_status = AesUpdateStreamDecrypt(key_handle,
                                             cipher_mode,
                                             input_length,
                                             input,
                                             output,
                                             HSE_SGT_OPTION_NONE);
    }

    return ele_hseb_to_psa_status(hseb_status);
}

psa_status_t ele_hseb_common_cipher_update(hseKeyHandle_t key_handle,
                                           ele_hseb_cipher_operation_t *operation,
                                           const uint8_t *input,
                                           size_t input_length,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{
    psa_status_t status                    = PSA_ERROR_CORRUPTION_DETECTED;
    size_t remaining_input_length          = 0u;
    size_t usable_input_length             = 0u;
    bool is_chunk_full                     = false;
    size_t chunk_overflow                  = 0u;
    size_t expected_output_size            = 0u;
    size_t length_of_input_copied_to_chunk = 0u;

    *output_length = 0u;

    /* Check for a potentially small output buffer size */
    expected_output_size = output_size == 0u ? output_size : input_length;
    if (output_size < expected_output_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* 1. Fill the chunk buff as much as we can
     * 2. If chunk buff full
     *     2a. call first update
     *     2b. else we are done with this update with success.
     * 3. If we have additional data
     *     3a. If additional data length >= AES blocklen, do update on all full blocks and go to 3.
     *     3b. If additional data length <  AES blocklen, fill the chunk buffer
     * 4. Done
     */

    // 1. Fill the chunk buff as much as we can
    length_of_input_copied_to_chunk = ele_hseb_manage_chunk(operation->chunk,
                                                            sizeof(operation->chunk),
                                                            &(operation->chunk_length),
                                                            input,
                                                            input_length,
                                                            &is_chunk_full,
                                                            &chunk_overflow);

    // 2. If chunk buff full
    if (true == is_chunk_full) {
        // 2a. Call first update on chunk, clear chunk length
        status = cipher_update_compute(key_handle,
                                       operation->cipher_mode,
                                       operation->chunk_length,
                                       operation->chunk,
                                       output,
                                       operation->cipher_direction);

        *output_length          = *output_length + operation->chunk_length;
        output                  = output + operation->chunk_length;
        input                   = input + length_of_input_copied_to_chunk;
        operation->chunk_length = 0u;
    } else {
        // 2b. Else there is nothing else to do; exit soon with success
        *output_length = 0u;
        status         = PSA_SUCCESS;
        goto exit;
    }

    /* Check if the first UPDATE call passed */
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    // 3. If we have additional data
    if (input_length > length_of_input_copied_to_chunk) {
        remaining_input_length = input_length - length_of_input_copied_to_chunk;

        // 3a. If additional data length >= AES blocklength (i.e. we can process at least some of it)
        if (remaining_input_length >= AES_BLOCK_LENGTH) {
            usable_input_length = (remaining_input_length / AES_BLOCK_LENGTH) * AES_BLOCK_LENGTH;

            status = cipher_update_compute(key_handle,
                                           operation->cipher_mode,
                                           usable_input_length,
                                           input,
                                           output,
                                           operation->cipher_direction);

            /* This should never happen, but we check just in case */
            if (mcux_psa_add_size_t_wrapcheck(*output_length, usable_input_length)) {
                status = PSA_ERROR_BUFFER_TOO_SMALL;
                goto exit;
            }

            *output_length = *output_length + usable_input_length;
            input          = input + usable_input_length;
        }

        // There still might be a length of data < AES_BLOCK_LENGTH, save it
        remaining_input_length = remaining_input_length % AES_BLOCK_LENGTH;
        if (0u < remaining_input_length) {
            // 3b. Fill the chunk buffer
            (void) ele_hseb_manage_chunk(operation->chunk,
                                         sizeof(operation->chunk),
                                         &(operation->chunk_length),
                                         input,
                                         remaining_input_length,
                                         &is_chunk_full,
                                         &chunk_overflow);
        }
    }
    // 4. Done

exit:
    return status;
}


static psa_status_t cipher_finish_compute(hseKeyHandle_t key_handle,
                                          hseCipherBlockMode_t cipher_mode,
                                          uint32_t input_length,
                                          const uint8_t *input,
                                          uint8_t *output,
                                          hseCipherDir_t cipher_direction)
{
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;

    if (HSE_CIPHER_DIR_ENCRYPT == cipher_direction) {
        hseb_status = AesFinishStreamEncrypt(key_handle,
                                             cipher_mode,
                                             input_length,
                                             input,
                                             output,
                                             HSE_SGT_OPTION_NONE);
    } else { /* HSE_CIPHER_DIR_DECRYPT */
        hseb_status = AesFinishStreamDecrypt(key_handle,
                                             cipher_mode,
                                             input_length,
                                             input,
                                             output,
                                             HSE_SGT_OPTION_NONE);
    }

    return ele_hseb_to_psa_status(hseb_status);
}

psa_status_t ele_hseb_common_cipher_finish(hseKeyHandle_t key_handle,
                                           ele_hseb_cipher_operation_t *operation,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->need_full_block) {
        /* As per HSEB spec, we must call FINISH to close off the operation,
         * so we call it on invalid data even if we correctly computed
         * everything during the very last UPDATE.
         */
        (void) cipher_finish_compute(key_handle,
                                     operation->cipher_mode,
                                     0u,
                                     NULL,
                                     NULL,
                                     operation->cipher_direction);

        /* If we needed chunk mgmt and processed everything,
         * we are successful
         */
        if (operation->chunk_length == 0u) {
            status = PSA_SUCCESS;
        } else {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }

        /* In this branch this is always the case */
        *output_length = 0u;
    } else {
        if (0u < operation->chunk_length) {
            /* One last computation for the unprocessed chunks of non-blocksize
             * dependent ciphers
             */
            status = cipher_finish_compute(key_handle,
                                           operation->cipher_mode,
                                           operation->chunk_length,
                                           operation->chunk,
                                           output,
                                           operation->cipher_direction);
        } else {
            status = PSA_SUCCESS;
        }

        /* On failure, we should explicitly set output length to 0 */
        if (PSA_SUCCESS == status) {
            *output_length = operation->chunk_length;
        } else {
            *output_length = 0u;
        }
    }

    return status;
}

psa_status_t ele_hseb_common_cipher_start_stream_internal(
    ele_hseb_cipher_operation_t *operation,
    hseKeyHandle_t key_handle,
    const uint8_t *iv)
{
    psa_status_t status          = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;

    if (HSE_CIPHER_DIR_ENCRYPT == operation->cipher_direction) {
        hseb_status = AesStartStreamEncrypt(key_handle,
                                            operation->cipher_mode,
                                            iv,
                                            0u, NULL, NULL,
                                            HSE_SGT_OPTION_NONE);
    } else { /* HSE_CIPHER_DIR_DECRYPT */
        hseb_status = AesStartStreamDecrypt(key_handle,
                                            operation->cipher_mode,
                                            iv,
                                            0u, NULL, NULL,
                                            HSE_SGT_OPTION_NONE);
    }
    status = ele_hseb_to_psa_status(hseb_status);

    return status;
}

psa_status_t ele_hseb_common_cipher_setup(hseKeyHandle_t key_handle,
                                          ele_hseb_cipher_operation_t *operation,
                                          const psa_key_attributes_t *attributes,
                                          const uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          psa_algorithm_t alg,
                                          hseCipherDir_t cipher_direction)
{
    psa_key_type_t key_type   = psa_get_key_type(attributes);
    size_t key_bits           = psa_get_key_bits(attributes);
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;

    /* Here we only set up the internal cipher driver context.
     * Because HSEB streaming mode requires the IV data in the START step,
     * we defer the HSEB cipher start call to ele_hseb_*_cipher_set_iv().
     */

    if (PSA_KEY_TYPE_AES != key_type) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->cipher_mode = psa_to_hseb_cipher_mode(alg);
    if (HSE_CIPHER_BLOCK_MODE_NULL == operation->cipher_mode) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (sizeof(operation->key) < key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    operation->cipher_direction = cipher_direction;
    operation->key_bits = key_bits;
    (void) memcpy(operation->key, key_buffer, key_buffer_size);

    if (PSA_ALG_ECB_NO_PADDING == alg) {
        /* ECB does not take IV, so we mustn't defer the operation start call
         * to ele_hseb_*_cipher_set_iv(), since that will never
         * be called.
         */
        status = ele_hseb_common_cipher_start_stream_internal(operation, key_handle, NULL);
    } else {
        status = PSA_SUCCESS;
    }

    /* If non-blocksize input is not supported, we need to manage our chunk */
    if (false == ele_hseb_is_cipher_input_length_correct(1u, alg, key_type)) {
        operation->need_full_block = true;
    }

    return status;
}
