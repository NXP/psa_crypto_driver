/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_ele_hseb_translate.h"

psa_status_t ele_hseb_to_psa_status(hseSrvResponse_t ele_hseb_status)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;

    switch (ele_hseb_status) {
        case HSE_SRV_RSP_OK:
            psa_status = PSA_SUCCESS;
            break;
        case HSE_SRV_RSP_VERIFY_FAILED:
            psa_status = PSA_ERROR_INVALID_SIGNATURE;
            break;
        case HSE_SRV_RSP_INVALID_PARAM:
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case HSE_SRV_RSP_NOT_SUPPORTED:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            break;
        case HSE_SRV_RSP_NOT_ENOUGH_SPACE:
            psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
            break;
        case HSE_SRV_RSP_STREAMING_MODE_FAILURE:
            psa_status = PSA_ERROR_BAD_STATE;
            break;
        case HSE_SRV_RSP_MEMORY_FAILURE:
            psa_status = PSA_ERROR_HARDWARE_FAILURE;
            break;
        case HSE_SRV_RSP_GENERAL_ERROR:
            psa_status = PSA_ERROR_GENERIC_ERROR;
            break;
        default:
            psa_status = PSA_ERROR_GENERIC_ERROR;
            break;
    }

    return psa_status;
}

psa_status_t psa_to_ele_hseb_hash(psa_algorithm_t alg,
                                  hseHashAlgo_t *hseb_hash)
{
    psa_status_t status          = PSA_SUCCESS;
    psa_algorithm_t psa_hash_alg = PSA_ALG_GET_HASH(alg);

    switch (psa_hash_alg) {
        case PSA_ALG_SHA_1:
            *hseb_hash = HSE_HASH_ALGO_SHA_1;
            break;
        case PSA_ALG_SHA_224:
            *hseb_hash = HSE_HASH_ALGO_SHA2_224;
            break;
        case PSA_ALG_SHA_256:
            *hseb_hash = HSE_HASH_ALGO_SHA2_256;
            break;
        case PSA_ALG_SHA_384:
            *hseb_hash = HSE_HASH_ALGO_SHA2_384;
            break;
        case PSA_ALG_SHA_512:
            *hseb_hash = HSE_HASH_ALGO_SHA2_512;
            break;
        case PSA_ALG_SHA_512_224:
            *hseb_hash = HSE_HASH_ALGO_SHA2_512_224;
            break;
        case PSA_ALG_SHA_512_256:
            *hseb_hash = HSE_HASH_ALGO_SHA2_512_256;
            break;
        case PSA_ALG_SHA3_224:
            *hseb_hash = HSE_HASH_ALGO_SHA3_224;
            break;
        case PSA_ALG_SHA3_256:
            *hseb_hash = HSE_HASH_ALGO_SHA3_256;
            break;
        case PSA_ALG_SHA3_384:
            *hseb_hash = HSE_HASH_ALGO_SHA3_384;
            break;
        case PSA_ALG_SHA3_512:
            *hseb_hash = HSE_HASH_ALGO_SHA3_512;
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    return status;
}

psa_status_t ele_hseb_to_psa_hash(hseHashAlgo_t hseb_hash,
                                  psa_algorithm_t *alg)
{
    psa_status_t status = PSA_SUCCESS;

    switch (hseb_hash) {
        case HSE_HASH_ALGO_SHA_1:
            *alg = PSA_ALG_SHA_1;
            break;
        case HSE_HASH_ALGO_SHA2_224:
            *alg = PSA_ALG_SHA_224;
            break;
        case HSE_HASH_ALGO_SHA2_256:
            *alg = PSA_ALG_SHA_256;
            break;
        case HSE_HASH_ALGO_SHA2_384:
            *alg = PSA_ALG_SHA_384;
            break;
        case HSE_HASH_ALGO_SHA2_512:
            *alg = PSA_ALG_SHA_512;
            break;
        case HSE_HASH_ALGO_SHA2_512_224:
            *alg = PSA_ALG_SHA_512_224;
            break;
        case HSE_HASH_ALGO_SHA2_512_256:
            *alg = PSA_ALG_SHA_512_256;
            break;
        case HSE_HASH_ALGO_SHA3_224:
            *alg = PSA_ALG_SHA3_224;
            break;
        case HSE_HASH_ALGO_SHA3_256:
            *alg = PSA_ALG_SHA3_256;
            break;
        case HSE_HASH_ALGO_SHA3_384:
            *alg = PSA_ALG_SHA3_384;
            break;
        case HSE_HASH_ALGO_SHA3_512:
            *alg = PSA_ALG_SHA3_512;
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    return status;
}
