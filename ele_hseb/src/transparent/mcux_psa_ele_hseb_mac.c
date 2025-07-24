/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_ele_hseb_mac.c
 *
 * This file contains the implementation of the entry points associated to the
 * mac capability as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_ele_hseb_init.h"
#include "mcux_psa_ele_hseb_mac.h"
#include "mcux_psa_ele_hseb_translate.h"
#include "mcux_psa_ele_hseb_key_management.h"

#include "hse_host_mac.h"
#include "hse_host_import_key.h"

static psa_status_t psa_to_hseb_mac_scheme(psa_algorithm_t alg,
                                           hseMacScheme_t *hseb_mac_scheme)
{
    psa_status_t status = PSA_SUCCESS;

    /* SHA3 unsupported for HMAC */
    switch (alg) {
        case PSA_ALG_CMAC:
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_CMAC;
            hseb_mac_scheme->sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_1):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA_1;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_224):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_224;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_256):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_256;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_384):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_384;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_512):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_512;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_512_224):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_512_224;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_512_256):
            hseb_mac_scheme->macAlgo = HSE_MAC_ALGO_HMAC;
            hseb_mac_scheme->sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_512_256;
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    return status;
}

psa_status_t ele_hseb_transparent_mac_compute(const psa_key_attributes_t *attributes,
                                              const uint8_t *key_buffer,
                                              size_t key_buffer_size,
                                              psa_algorithm_t alg,
                                              const uint8_t *input,
                                              size_t input_length,
                                              uint8_t *mac,
                                              size_t mac_size,
                                              size_t *mac_length)
{
    psa_status_t status            = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status   = HSE_SRV_RSP_GENERAL_ERROR;
    psa_key_type_t key_type        = psa_get_key_type(attributes);
    size_t key_bits                = psa_get_key_bits(attributes);
    hseMacScheme_t hseb_mac_scheme = { 0 };
    hseKeyHandle_t key_handle      = { 0 };
    hseKeyType_t hse_key_type      = { 0 };

    /* Key buffer or size or mac buffer or mac length can't be NULL */
    if (NULL == key_buffer || 0u == key_buffer_size ||
        NULL == mac        || NULL == mac_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Algorithm must be a MAC algorithm */
    if (false == PSA_ALG_IS_MAC(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_to_hseb_mac_scheme(alg, &hseb_mac_scheme);
    if (PSA_SUCCESS != status) {
        return status;
    }

    hse_key_type = HSE_MAC_ALGO_HMAC == hseb_mac_scheme.macAlgo
                    ? HSE_KEY_TYPE_HMAC
                    : HSE_KEY_TYPE_AES;

    // TODO HMAC should also be supported; currently running into issues with
    //      importing HMAC keys
    if (HSE_KEY_TYPE_AES != hse_key_type) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Check MAC output buffer size */
    if (mac_size < PSA_MAC_LENGTH(key_type, key_bits, alg)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    hseb_status = LoadSymKey(&key_handle,
                             false,
                             hse_key_type,
                             (uint16_t) (PSA_BITS_TO_BYTES(key_bits)),
                             key_buffer);
    if (HSE_SRV_RSP_OK != hseb_status) {
        status = ele_hseb_to_psa_status(hseb_status);
        goto exit;
    }

    *mac_length = mac_size;

    if (HSE_MAC_ALGO_CMAC == hseb_mac_scheme.macAlgo) {
        hseb_status = AesCmacGenerate(key_handle, input_length, input,
                                      (uint32_t *) mac_length, mac, HSE_SGT_OPTION_NONE);
    } else { /* HSE_MAC_ALGO_HMAC */
        const hseHashAlgo_t hash_alg = hseb_mac_scheme.sch.hmac.hashAlgo;
        hseb_status = HmacGenerate(key_handle, hash_alg, input_length, input,
                                   (uint32_t *) mac_length, mac, HSE_SGT_OPTION_NONE);
    }

    if (HSE_SRV_RSP_OK != hseb_status) {
        *mac_length = 0u;
        status = ele_hseb_to_psa_status(hseb_status);
        goto exit;
    }

    /* All went well, set retvals */
    *mac_length = PSA_MAC_LENGTH(key_type, key_bits, alg);
    status      = PSA_SUCCESS;

exit:

    (void) ele_hseb_delete_key(&key_handle, HSE_ERASE_NOT_USED);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}
