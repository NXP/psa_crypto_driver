/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_ELE_HSEB_OPAQUE_KEY_GENERATION_H
#define MCUX_PSA_ELE_HSEB_OPAQUE_KEY_GENERATION_H

/** \file mcux_psa_ele_hseb_opaque_key_generation.h
 *
 * This file contains the declaration of the entry points associated to the
 * key generation as described by the PSA Cryptoprocessor Driver interface
 * specification.
 */

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Generate an opaque key inside the HSE-B keystore.
 *
 * The key is generated entirely inside HSE-B and never leaves the hardware
 * in plaintext. On success, \p key_buffer receives the HSE key handle that
 * identifies the generated key slot. Supported key types are AES, HMAC,
 * ECC key pairs, and RSA key pairs (NVM location only for RSA).
 *
 * \param[in]  attributes        Attributes of the key to generate.
 * \param[out] key_buffer        Buffer to receive the opaque key handle.
 * \param[in]  key_buffer_size   Size in bytes of \p key_buffer.
 * \param[out] key_buffer_length On success, set to the number of bytes
 *                               written into \p key_buffer.
 *
 * \retval PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *         failure.
 */
psa_status_t ele_hseb_opaque_generate_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length);

/**
 * \brief Return the buffer size required to store an HSE-B opaque key handle.
 *
 * The opaque key buffer for HSE-B holds an \c hseKeyHandle_t value. This
 * function returns the appropriate size for that handle, derived from the
 * key attributes, so that the PSA core can allocate a correctly sized buffer
 * before calling \ref ele_hseb_opaque_generate_key or the import entry point.
 *
 * \param[in] attributes Attributes of the key whose buffer size is queried.
 *
 * \retval The number of bytes required to store the opaque key handle on
 *         success, 0 on failure.
 */
size_t ele_hseb_opaque_get_key_buffer_size(const psa_key_attributes_t *attributes);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_ELE_HSEB_OPAQUE_KEY_GENERATION_H */
