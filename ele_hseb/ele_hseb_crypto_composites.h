/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELE_HSEB_CRYPTO_COMPOSITES_H
#define ELE_HSEB_CRYPTO_COMPOSITES_H

/** \file ele_hseb_crypto_composites.h
 *
 * This file contains the declaration of the composite context structures
 * related to the ELE HSEB driver.
 *
 */

#include "hse_interface.h"

typedef struct {
    uint8_t dummy; // Prepared for future support of multipart MAC
} ele_hseb_transparent_mac_operation_t;

typedef struct {
    uint8_t dummy; // Prepared for future support of multipart AEAD
} ele_hseb_transparent_aead_operation_t;

#endif /* ELE_HSEB_CRYPTO_COMPOSITES_H */
