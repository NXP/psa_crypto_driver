/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_ELE_HSEB_TRANSLATE_H
#define MCUX_PSA_ELE_HSEB_TRANSLATE_H

/** \file mcux_psa_ele_hseb_translate.h
 *
 * This file contains the declaration of the entry points associated
 * with common value translation functions utilized by the ELE HSEB PSA port
 * driver.
 *
 * \note This header should not be included by ele_hseb.h, as it is internal
 *       only.
 *
 */

#include "psa/crypto.h"
#include "hse_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief  Translate ELE_HSEB service status to PSA status
 *
 * \retval PSA_SUCCESS on success. Error code from psa_status_t on
 *         failure
 */
psa_status_t ele_hseb_to_psa_status(hseSrvResponse_t ele_hseb_status);

/**
 * \brief Translate ELE_HSEB hash algorithm to PSA algorithm
 *
 * \param[in]  hseb_hash ELE HSEB hash algorithm to be translated
 * \param[out] alg       Translated PSA alg value
 *
 * \retval PSA_SUCCESS on success or PSA_ERROR_NOT_SUPPORTED in case
 *         no translation can be made
 */
psa_status_t ele_hseb_to_psa_hash(hseHashAlgo_t hseb_hash,
                                  psa_algorithm_t *alg);

/**
 * \brief Translate PSA algorithm to ELE_HSEB hash algorithm
 *
 * \param[in]  alg       PSA alg algorithm to be translated
 * \param[out] hseb_hash Translated ELE HSEB hash algorithm
 *
 * \retval PSA_SUCCESS on success or PSA_ERROR_NOT_SUPPORTED in case
 *         no translation can be made
 */
psa_status_t psa_to_ele_hseb_hash(psa_algorithm_t alg,
                                  hseHashAlgo_t *hseb_hash);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_ELE_HSEB_TRANSLATE_H */
