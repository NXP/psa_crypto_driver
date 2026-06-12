/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_SGI_COMMON_KEY_MANAGEMENT_H
#define MCUX_PSA_SGI_COMMON_KEY_MANAGEMENT_H

/**
 * @file  mcux_psa_sgi_common_key_management.h
 * @brief Common SGI key management utilities shared between transparent and
 *        opaque PSA crypto drivers.
 *
 * This header provides helper functions that create and configure SGI key
 * descriptors from PSA key attributes, eliminating code duplication across
 * the transparent and opaque driver entry points.
 */

#include "psa/crypto.h"

#include <mcuxClKey.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create and initialize an SGI key descriptor from PSA key attributes.
 *
 * For LOCAL_STORAGE keys, the key material is set as loaded-in-place.
 * For opaque key locations, the key data pointers are configured but
 * loading is deferred (the caller or an oracle is responsible).
 *
 * The PSA key attributes pointer is stored as auxiliary data in the
 * descriptor for downstream use by crypto operations.
 *
 * @param[in]  attributes         PSA key attributes (type, bits, usage, lifetime).
 * @param[in]  key_buffer         Pointer to raw key material.
 * @param[in]  key_buffer_size    Size of @p key_buffer in bytes.
 * @param[out] out_key_descriptor Pointer to a key descriptor to populate.
 *
 * @retval PSA_SUCCESS              Key descriptor configured successfully.
 * @retval PSA_ERROR_INVALID_ARGUMENT  @p out_key_descriptor is NULL.
 * @retval PSA_ERROR_NOT_SUPPORTED  Key type or size is not supported by SGI.
 */
psa_status_t sgi_create_key_descriptor(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    mcuxClKey_Descriptor_t *out_key_descriptor);

#ifdef __cplusplus
}
#endif

#endif /* MCUX_PSA_SGI_COMMON_KEY_MANAGEMENT_H */
