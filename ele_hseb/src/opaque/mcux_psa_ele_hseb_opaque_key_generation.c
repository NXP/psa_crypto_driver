/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_ele_hseb_opaque_key_generation.c
 *
 * This file contains the implementation of the entry points associated to the
 * key generation as described by the PSA Cryptoprocessor Driver interface
 * specification.
 */

#include <stdbool.h>

#include "mcux_psa_ele_hseb_opaque_key_generation.h"
#include "mcux_psa_ele_hseb_key_locations.h"
#include "mcux_psa_ele_hseb_init.h"
#include "mcux_psa_ele_hseb_utils.h"
#include "mcux_psa_ele_hseb_translate.h"
#include "mcux_psa_ele_hseb_key_management.h"
#include "hse_host_import_key.h"
#include "hse_keys_allocator.h"

#include "mcux_psa_util_wrapcheck_static_inline.h"

static uint8_t muIf = 0U;
static uint8_t muChannelIdx = 1U;

#define RSA_DEFAULT_PUBLIC_EXPONENT        (65537u)
#define RSA_DEFAULT_PUBLIC_EXPONENT_LENGTH (3u)

static psa_status_t hseb_generate_key_req(hseKeyGenerateSrv_t *key_gen_srv,
                                          hseKeyHandle_t *target_key_handle,
                                          bool is_nvm)
{
    hseSrvResponse_t    hseSrvResponse = HSE_SRV_RSP_GENERAL_ERROR;
    hseSrvDescriptor_t *pHseSrvDesc   = &gHseSrvDesc[muIf][muChannelIdx];

    hseSrvResponse = HKF_AllocKeySlot((is_nvm ? NVM_KEY : RAM_KEY), key_gen_srv->keyInfo.keyType,
                                      key_gen_srv->keyInfo.keyBitLen,
                                      target_key_handle);
    if (HSE_SRV_RSP_OK != hseSrvResponse) {
        goto exit;
    }

    (void) memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pHseSrvDesc->srvId = HSE_SRV_ID_KEY_GENERATE;

    /* Caller has pre-filled all fields; patch in the allocated handle */
    key_gen_srv->targetKeyHandle  = *target_key_handle;
    pHseSrvDesc->hseSrv.keyGenReq = *key_gen_srv;

    hseSrvResponse = HSE_Send(muIf, muChannelIdx, gSyncTxOption, pHseSrvDesc);
    if (HSE_SRV_RSP_OK != hseSrvResponse) {
        (void) HKF_FreeKeySlot(target_key_handle);
    }
exit:
    return ele_hseb_to_psa_status(hseSrvResponse);
}

static psa_status_t hseb_generate_symmetric_key(const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                size_t *key_buffer_length,
                                                bool is_nvm)
{
    psa_status_t status               = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t alg               = psa_get_key_algorithm(attributes);
    psa_key_type_t key_type           = psa_get_key_type(attributes);
    size_t key_bits                   = psa_get_key_bits(attributes);
    psa_key_usage_t key_usage         = psa_get_key_usage_flags(attributes);

    uint16_t hse_key_bits             = 0u;
    hseKeyType_t hse_key_type         = { 0 };
    hseKeyHandle_t target_key_handle  = { 0 };
    hseKeyFlags_t hse_key_flags       = { 0 };
    hseKeyGenerateSrv_t key_gen_srv   = { 0 };
    hseAesBlockModeMask_t cipher_mask = cipher_mode_to_cipher_mask(psa_to_hseb_cipher_mode(alg));

    if (key_bits > (size_t) UINT16_MAX) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    hse_key_bits = (uint16_t) key_bits;

    if (PSA_KEY_TYPE_AES == key_type) {
        if (PSA_ALG_CMAC == alg) {
            hse_key_type = HSE_KEY_TYPE_AES;
        } else if (HSE_KU_AES_BLOCK_MODE_ANY != cipher_mask) {
            /* If it's not CMAC, it must be one of the supported block modes */
            hse_key_type = HSE_KEY_TYPE_AES;
        } else {
            /* If none of the above, we don't support it */
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
    } else if ((PSA_KEY_TYPE_HMAC == key_type) &&
               (true == is_mac_key_size_supported(key_type, key_bits))) {
        if (HSE_KU_AES_BLOCK_MODE_ANY != cipher_mask) {
            /* Key type is HMAC, but we got a block cipher alg */
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        hse_key_type = HSE_KEY_TYPE_HMAC;
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    /* Map the key permissions */
    psa_to_hseb_key_usage(key_usage, &hse_key_flags);

    key_gen_srv.keyInfo.keyType                   = hse_key_type;
    key_gen_srv.keyInfo.keyBitLen                 = hse_key_bits;
    key_gen_srv.keyInfo.keyFlags                  = hse_key_flags;
    key_gen_srv.keyInfo.specific.aesBlockModeMask = cipher_mask; /* Zero for MACs */
    key_gen_srv.keyGenScheme                      = HSE_KEY_GEN_SYM_RANDOM_KEY;

    status = hseb_generate_key_req(&key_gen_srv, &target_key_handle, is_nvm);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    ele_hseb_write_key_handle_to_buffer(key_buffer, key_buffer_length,
                                        &target_key_handle);
    status = PSA_SUCCESS;
exit:
    return status;
}

static psa_status_t hseb_generate_ecc_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length,
                                          bool is_nvm)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits           = psa_get_key_bits(attributes);
    psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);

    uint16_t hse_key_bits            = 0u;
    hseKeyType_t hse_key_type        = { 0 };
    hseKeyHandle_t target_key_handle = { 0 };
    hseKeyFlags_t hse_key_flags      = { 0 };
    hseEccCurveId_t hse_curve_id     = { 0 };
    hseKeyGenerateSrv_t key_gen_srv  = { 0 };

    status = psa_to_hseb_curve(attributes, &hse_curve_id);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    if (key_bits > (size_t) UINT16_MAX) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    hse_key_bits = (uint16_t) key_bits;
    hse_key_type = HSE_KEY_TYPE_ECC_PAIR;
    psa_to_hseb_key_usage(key_usage, &hse_key_flags);

    key_gen_srv.keyInfo.keyType             = hse_key_type;
    key_gen_srv.keyInfo.keyBitLen           = hse_key_bits;
    key_gen_srv.keyInfo.keyFlags            = hse_key_flags;
    key_gen_srv.keyInfo.specific.eccCurveId = hse_curve_id;
    key_gen_srv.sch.eccKey.pPubKey          = NULL_HOST_ADDR; /* Not used */
    key_gen_srv.keyGenScheme                = HSE_KEY_GEN_ECC_KEY_PAIR;

    status = hseb_generate_key_req(&key_gen_srv, &target_key_handle, is_nvm);
    if (PSA_SUCCESS == status) {
        ele_hseb_write_key_handle_to_buffer(key_buffer, key_buffer_length,
                                            &target_key_handle);
    }
exit:
    return status;
}

static psa_status_t hseb_generate_rsa_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length,
                                          bool is_nvm)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits           = psa_get_key_bits(attributes);
    psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);

    uint16_t hse_key_bits            = 0u;
    hseKeyType_t hse_key_type        = { 0 };
    hseKeyHandle_t target_key_handle = { 0 };
    hseKeyFlags_t hse_key_flags      = { 0 };
    hseKeyGenerateSrv_t key_gen_srv  = { 0 };

    /* PSA currently does not support passing custom pubexps to drivers,
     * so we go with the default used by PSA.
     */
    uint32_t public_exponent        = RSA_DEFAULT_PUBLIC_EXPONENT;
    uint32_t public_exponent_length = RSA_DEFAULT_PUBLIC_EXPONENT_LENGTH;

    if (key_bits > (size_t) UINT16_MAX) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    hse_key_bits = (uint16_t) key_bits;
    hse_key_type = HSE_KEY_TYPE_RSA_PAIR;
    psa_to_hseb_key_usage(key_usage, &hse_key_flags);

    key_gen_srv.keyInfo.keyType                  = hse_key_type;
    key_gen_srv.keyInfo.keyBitLen                = hse_key_bits;
    key_gen_srv.keyInfo.keyFlags                 = hse_key_flags;
    key_gen_srv.keyInfo.specific.pubExponentSize = public_exponent_length;
    key_gen_srv.sch.rsaKey.pPubExp               = HSE_PTR_TO_HOST_ADDR(&public_exponent);
    key_gen_srv.sch.rsaKey.pubExpLength          = public_exponent_length;
    key_gen_srv.sch.rsaKey.pModulus              = NULL_HOST_ADDR; /* Not used */
    key_gen_srv.keyGenScheme                     = HSE_KEY_GEN_RSA_KEY_PAIR;

    status = hseb_generate_key_req(&key_gen_srv, &target_key_handle, is_nvm);
    if (PSA_SUCCESS == status) {
        ele_hseb_write_key_handle_to_buffer(key_buffer, key_buffer_length,
                                            &target_key_handle);
    }
exit:
    return status;
}

psa_status_t ele_hseb_opaque_generate_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length)
{
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_lifetime_t lifetime = psa_get_key_lifetime(attributes);
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
    psa_key_type_t key_type     = psa_get_key_type(attributes);
    bool is_nvm                 = false;

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (PSA_KEY_LOCATION_ELE_HSEB == location) {
        /* Set the NVM flag if the key is persistent */
        is_nvm = !PSA_KEY_LIFETIME_IS_VOLATILE(lifetime);

        if (true == PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type)) {
            status = hseb_generate_symmetric_key(attributes,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 key_buffer_length,
                                                 is_nvm);
        } else if (true == PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
            status = hseb_generate_ecc_key(attributes,
                                           key_buffer,
                                           key_buffer_size,
                                           key_buffer_length,
                                           is_nvm);
        } else if ((true == PSA_KEY_TYPE_IS_RSA(key_type)) &&
                   (true == is_nvm)) {
            /* RSA keys must be NVM keys, fail otherwise; HSEB limitation */
            status = hseb_generate_rsa_key(attributes,
                                           key_buffer,
                                           key_buffer_size,
                                           key_buffer_length,
                                           is_nvm);
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

size_t ele_hseb_opaque_get_key_buffer_size(const psa_key_attributes_t *attributes)
{
    size_t buffer_size = 0u;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

    switch (location) {
        case PSA_KEY_LOCATION_ELE_HSEB:
            buffer_size = sizeof(hseKeyHandle_t);
            break;
        /* Other locations to be added if needed */
        default:
            buffer_size = 0u;
            break;
    }

    return buffer_size;
}
