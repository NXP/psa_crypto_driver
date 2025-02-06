/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_S2XX_OPAQUE_MAC_H
#define MCUX_PSA_S2XX_OPAQUE_MAC_H

/** \file mcux_psa_s2xx_psa_opaque_mac.h
 *
 * This file contains the declaration of the entry points associated to the
 * mac capability (single-part only, multi-part (not supported in ele)) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "psa/crypto.h"
#include "mcux_psa_s2xx_common_init.h"

#ifdef __cplusplus
extern "C" {
#endif

psa_status_t ele_s2xx_opaque_mac_compute(const psa_key_attributes_t *attributes,
                                         const uint8_t *key_buffer,
                                         size_t key_buffer_size,
                                         psa_algorithm_t alg,
                                         const uint8_t *input,
                                         size_t input_length,
                                         uint8_t *mac,
                                         size_t mac_size,
                                         size_t *mac_length);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_S2XX_OPAQUE_MAC_H */
