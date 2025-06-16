/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SGI_CRYPTO_PRIMITIVES_H
#define SGI_CRYPTO_PRIMITIVES_H

/** \file sgi_crypto_primtives.h
 *
 * This file contains the declaration of the context structures related
 * to the SGI HW
 *
 */

#include <mcuxClHash.h> // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>

#include <mcuxClMacModes.h>

typedef struct
{
    uint32_t ctx[MCUXCLHASH_CONTEXT_SIZE_SHA2_512_IN_WORDS];
} mcux_sgi_hash_operation_t;


typedef struct {
    uint32_t ctx[MCUXCLMAC_CONTEXT_SIZE_IN_WORDS];
} sgi_mac_operation_t;
#endif /* SGI_CRYPTO_PRIMITIVES_H */
