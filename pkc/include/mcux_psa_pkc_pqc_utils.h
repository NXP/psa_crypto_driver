/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_PKC_PQC_UTILS_H
#define MCUX_PSA_PKC_PQC_UTILS_H

/** \file mcux_psa_pkc_utils.h
 *
 * This file contains declarations for PQC-related utility functions.
 */


#include "pkc.h"

#include <mcuxClMlDsa.h>
#include <internal/mcuxClKey_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Deterministically generate an ML-DSA key pair from a seed
 *
 * \param[in]  attributes          Attributes of the key to use
 * \param[in]  seed                Buffer holding the seed material
 * \param[in]  seed_size           Size in bytes of the seed buffer
 * \param[out] private_key         Buffer to hold the generated private key
 * \param[in]  private_key_size    Size in bytes of the private_key buffer
 * \param[out] private_key_length  Size in bytes of the generated private key
 * \param[out] public_key          Buffer to hold the generated public key
 * \param[in]  public_key_size     Size in bytes of the public_key buffer
 * \param[out] public_key_length   Size in bytes of the generated public key
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t pkc_ml_dsa_generate_key_from_seed(const psa_key_attributes_t *attributes,
                                               const uint8_t *seed,
                                               size_t seed_size,
                                               uint8_t *private_key,
                                               size_t private_key_size,
                                               size_t *private_key_length,
                                               uint8_t *public_key,
                                               size_t public_key_size,
                                               size_t *public_key_length);

/**
 * @brief Get Module-Lattice-based key type key sizes based on PSA key attributes
 *
 * Retrieves the private and public key sizes in bytes for the
 * specified ML key type family (ML-DSA, ML-KEM).
 *
 * @param[in]  attributes     PSA key attributes
 * @param[out] priv_key_size  Private key size in bytes
 * @param[out] pub_key_size   Public key size in bytes
 *
 * @return PSA_SUCCESS on success
 * @return PSA_ERROR_NOT_SUPPORTED if curve is not supported
 * @return PSA_ERROR_INVALID_ARGUMENT if parameters are NULL
 */
psa_status_t get_ml_key_sizes(const psa_key_attributes_t *attributes,
                              size_t *priv_key_size,
                              size_t *pub_key_size);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_PKC_PQC_UTILS_H */
