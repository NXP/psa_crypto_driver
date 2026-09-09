/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_ELE_HSEB_COMMON_CIPHER_H
#define MCUX_PSA_ELE_HSEB_COMMON_CIPHER_H

/** \file mcux_psa_ele_hseb_common_cipher.h
 *
 * This file contains common declarations used by the transparent and opaque
 * cipher drivers.
 *
 */

#include "mcux_psa_ele_hseb_common_init.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Check whether the input length is valid for the given cipher algorithm
 *        and key type
 *
 * \param[in] input_length Size in bytes of the input data
 * \param[in] alg          Algorithm to be used for which
 *                         PSA_ALG_IS_CIPHER(alg) is true
 * \param[in] key_type     Type of the key to be used
 *
 * \retval  true if the input length is valid for the algorithm and key type,
 *          false otherwise
 */
bool ele_hseb_is_cipher_input_length_correct(size_t input_length,
                                             psa_algorithm_t alg,
                                             psa_key_type_t key_type);

/*!
 * \brief Check whether the key bit size is valid for the AES cipher
 *
 * \param[in] key_bits Bit size of the key
 *
 * \retval  true if the key bit size is valid for AES, false otherwise
 */
bool ele_hseb_is_cipher_key_bit_size_valid(size_t key_bits);

/*!
 * \brief Encrypt or decrypt a message fragment in an active cipher operation
 *
 * \param[in]     key_handle    Handle of the key to use for the operation
 * \param[in,out] operation     Multipart operation context
 * \param[in]     input         Buffer holding the input data
 * \param[in]     input_length  Size in bytes of the input data
 * \param[out]    output        Buffer holding the output data
 * \param[in]     output_size   Size in bytes of the output buffer
 * \param[out]    output_length Size in bytes of the written output data
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t ele_hseb_common_cipher_update(hseKeyHandle_t key_handle,
                                           ele_hseb_cipher_operation_t *operation,
                                           const uint8_t *input,
                                           size_t input_length,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length);

/*!
 * \brief Start a streaming cipher operation using the provided key and IV
 *
 * \param[in,out] operation  Multipart operation context
 * \param[in]     key_handle Handle of the key to use for the operation
 * \param[in]     iv         Buffer holding the initialization vector
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t ele_hseb_common_cipher_start_stream_internal(
    ele_hseb_cipher_operation_t *operation,
    hseKeyHandle_t key_handle,
    const uint8_t *iv);

/*!
 * \brief Perform the setup step for a multipart cipher operation
 *
 * \param[in]     key_handle        Handle of the key to use for the operation
 * \param[in,out] operation         Multipart operation context
 * \param[in]     attributes        Key attributes
 * \param[in]     key_buffer        Buffer holding key material
 * \param[in]     key_buffer_size   Size in bytes of the key
 * \param[in]     alg               Algorithm to be used for which
 *                                  PSA_ALG_IS_CIPHER(alg) is true
 * \param[in]     cipher_direction  Direction of the cipher operation
 *                                  (encrypt or decrypt)
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t ele_hseb_common_cipher_setup(hseKeyHandle_t key_handle,
                                          ele_hseb_cipher_operation_t *operation,
                                          const psa_key_attributes_t *attributes,
                                          const uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          psa_algorithm_t alg,
                                          hseCipherDir_t cipher_direction);

/*!
 * \brief Finish encrypting or decrypting a message in a cipher operation
 *
 * \param[in]     key_handle    Handle of the key to use for the operation
 * \param[in,out] operation     Multipart operation context
 * \param[out]    output        Buffer holding the output data
 * \param[in]     output_size   Size in bytes of the output buffer
 * \param[out]    output_length Size in bytes of the written output data
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t ele_hseb_common_cipher_finish(hseKeyHandle_t key_handle,
                                           ele_hseb_cipher_operation_t *operation,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_ELE_HSEB_COMMON_CIPHER_H */
