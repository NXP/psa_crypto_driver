/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_S2XX_OPAQUE_ASYMMETRIC_SIGNATURE_H
#define MCUX_PSA_S2XX_OPAQUE_ASYMMETRIC_SIGNATURE_H

/** \file mcux_psa_s2xx_opaque_asymmetric_signature.h
 *
 * This file contains the declaration of the entry points associated to the
 * asymmetric signature capability as described by the PSA Cryptoprocessor
 * Driver interface specification
 *
 */

#include "psa/crypto.h"
#include "mcux_psa_s2xx_common_init.h"

#ifdef __cplusplus
extern "C" {
#endif

psa_status_t ele_s2xx_opaque_sign_hash(const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer, size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *hash, size_t hash_length,
                                       uint8_t *signature, size_t signature_size,
                                       size_t *signature_length);

psa_status_t ele_s2xx_opaque_verify_hash(const psa_key_attributes_t *attributes,
                                         const uint8_t *key_buffer, size_t key_buffer_size,
                                         psa_algorithm_t alg,
                                         const uint8_t *hash, size_t hash_length,
                                         const uint8_t *signature, size_t signature_length);

psa_status_t ele_s2xx_opaque_sign_message(const psa_key_attributes_t *attributes,
                                          const uint8_t *key_buffer, size_t key_buffer_size,
                                          psa_algorithm_t alg,
                                          const uint8_t *input, size_t input_length,
                                          uint8_t *signature, size_t signature_size,
                                          size_t *signature_length);

psa_status_t ele_s2xx_opaque_verify_message(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input, size_t input_length,
                                            const uint8_t *signature, size_t signature_length);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_S2XX_OPAQUE_ASYMMETRIC_SIGNATURE_H */
