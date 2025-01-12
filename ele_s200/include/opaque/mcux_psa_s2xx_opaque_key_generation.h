/*
 * Copyright 2023 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef MCUX_PSA_S2XX_OPAQUE_KEY_GENERATION_H
#define MCUX_PSA_S2XX_OPAQUE_KEY_GENERATION_H

/** \file mcux_psa_s2xx_opaque_key_generation.h
 *
 * This file contains the declaration of the entry points associated to the
 * key generation (i.e. random generation and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

  /*!
 * \brief import opaque key
 */
psa_status_t s2xx_opaque_import_key(const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length, uint8_t *key_buffer,
    size_t key_buffer_size, size_t *key_buffer_length,  size_t *bits);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_S2XX_OPAQUE_KEY_GENERATION_H */
