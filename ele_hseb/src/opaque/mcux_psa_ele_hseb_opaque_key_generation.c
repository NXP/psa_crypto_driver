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

static psa_status_t translate_unstructured_key_parameters(size_t key_bits,
                                                          uint16_t *hse_key_bits,
                                                          psa_key_type_t key_type,
                                                          hseKeyType_t *hse_key_type,
                                                          psa_algorithm_t alg,
                                                          hseAesBlockModeMask_t *cipher_mask);

static psa_status_t hseb_generate_key_req(hseKeyGenerateSrv_t *key_gen_srv,
                                          hseKeyHandle_t *target_key_handle,
                                          bool is_nvm);

static psa_status_t hseb_generate_symmetric_key(const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                size_t *key_buffer_length,
                                                bool is_nvm);

static psa_status_t hseb_generate_ecc_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length,
                                          bool is_nvm);

static psa_status_t hseb_generate_rsa_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length,
                                          bool is_nvm);

static psa_status_t hseb_import_raw_key_req(hseImportKeySrv_t *import_key_srv,
                                            const hseKeyInfo_t *key_info,
                                            hseKeyHandle_t *target_key_handle,
                                            bool is_nvm);

static psa_status_t hseb_import_symmetric_key(const psa_key_attributes_t *attributes,
                                              const uint8_t *data,
                                              size_t data_length,
                                              uint8_t *key_buffer,
                                              size_t key_buffer_size,
                                              size_t *key_buffer_length,
                                              bool is_nvm);

static psa_status_t hseb_import_ecc_key(const psa_key_attributes_t *attributes,
                                        const uint8_t *data,
                                        size_t data_length,
                                        uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        size_t *key_buffer_length,
                                        bool is_nvm);

static uint8_t muIf = 0U;
static uint8_t muChannelIdx = 1U;

#define RSA_DEFAULT_PUBLIC_EXPONENT        (65537u)
#define RSA_DEFAULT_PUBLIC_EXPONENT_LENGTH (3u)

static psa_status_t translate_unstructured_key_parameters(size_t key_bits,
                                                          uint16_t *hse_key_bits,
                                                          psa_key_type_t key_type,
                                                          hseKeyType_t *hse_key_type,
                                                          psa_algorithm_t alg,
                                                          hseAesBlockModeMask_t *cipher_mask)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *cipher_mask = cipher_mode_to_cipher_mask(psa_to_hseb_cipher_mode(alg));

    if (key_bits > (size_t) UINT16_MAX) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    *hse_key_bits = (uint16_t) key_bits;

    if (PSA_KEY_TYPE_AES == key_type) {
        if (PSA_ALG_CMAC == alg) {
            *hse_key_type = HSE_KEY_TYPE_AES;
        } else if (HSE_KU_AES_BLOCK_MODE_ANY != *cipher_mask) {
            /* If it's not CMAC, it must be one of the supported block modes */
            *hse_key_type = HSE_KEY_TYPE_AES;
        } else {
            /* If none of the above, we don't support it */
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
    } else if ((PSA_KEY_TYPE_HMAC == key_type) &&
               (true == is_mac_key_size_supported(key_type, key_bits))) {
        if (HSE_KU_AES_BLOCK_MODE_ANY != *cipher_mask) {
            /* Key type is HMAC, but we got a block cipher alg */
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        *hse_key_type = HSE_KEY_TYPE_HMAC;
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    status = PSA_SUCCESS;
exit:
    return status;
}

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
    hseAesBlockModeMask_t cipher_mask = { 0 };

    status = translate_unstructured_key_parameters(key_bits, &hse_key_bits, key_type,
                                                   &hse_key_type, alg, &cipher_mask);
    if (PSA_SUCCESS != status) {
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
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits             = psa_get_key_bits(attributes);
    psa_key_usage_t key_usage   = psa_get_key_usage_flags(attributes);
    psa_key_type_t key_type     = psa_get_key_type(attributes);
    psa_ecc_family_t ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);

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

    if (((PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family) ||
         (PSA_ECC_FAMILY_MONTGOMERY == ecc_family)) &&
        (255u == key_bits)) {
        /* For these two curves, PSA spec wants to use 255, HSE-B wants to use 256 */
        hse_key_bits = 256u;
    } else {
        if (key_bits > (size_t) UINT16_MAX) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        hse_key_bits = (uint16_t) key_bits;
    }

    hse_key_type = HSE_KEY_TYPE_ECC_PAIR;
    psa_to_hseb_key_usage(key_usage, &hse_key_flags);

    key_gen_srv.keyInfo.keyType             = hse_key_type;
    key_gen_srv.keyInfo.keyBitLen           = hse_key_bits;
    key_gen_srv.keyInfo.keyFlags            = hse_key_flags;
    key_gen_srv.keyInfo.specific.eccCurveId = hse_curve_id;
    key_gen_srv.sch.eccKey.pPubKey          = NULL_HOST_ADDR; /* Not used */
    key_gen_srv.keyGenScheme                = HSE_KEY_GEN_ECC_KEY_PAIR;

    /* Make sure public part is exportable */
    key_gen_srv.keyInfo.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

    /* Keep only the relevant permissions, otherwise we cannot generate */
    if (true == PSA_ECC_FAMILY_IS_WEIERSTRASS(ecc_family)) {
        key_gen_srv.keyInfo.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_VERIFY |
                                         HSE_KF_USAGE_SIGN | HSE_KF_USAGE_EXCHANGE);
    } else if (PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family) {
        key_gen_srv.keyInfo.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_VERIFY |
                                         HSE_KF_USAGE_SIGN);
    } else if (PSA_ECC_FAMILY_MONTGOMERY == ecc_family) {
        key_gen_srv.keyInfo.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_EXCHANGE);
    } else {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

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
    key_gen_srv.sch.rsaKey.pPubExp               = (HOST_ADDR) &public_exponent;
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

size_t ele_hseb_opaque_size_function(const psa_key_attributes_t *attributes,
                                     const uint8_t *data,
                                     size_t data_length)
{
    (void) data;
    (void) data_length;
    return ele_hseb_opaque_get_key_buffer_size(attributes);
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

static psa_status_t hseb_import_raw_key_req(hseImportKeySrv_t *import_key_srv,
                                            const hseKeyInfo_t *key_info,
                                            hseKeyHandle_t *target_key_handle,
                                            bool is_nvm)
{
    hseSrvResponse_t    hseSrvResponse = HSE_SRV_RSP_GENERAL_ERROR;
    hseSrvDescriptor_t *pHseSrvDesc   = &gHseSrvDesc[muIf][muChannelIdx];

    hseSrvResponse = HKF_AllocKeySlot((is_nvm ? NVM_KEY : RAM_KEY), key_info->keyType,
                                      key_info->keyBitLen,
                                      target_key_handle);
    if (HSE_SRV_RSP_OK != hseSrvResponse) {
        goto exit;
    }

    (void) memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pHseSrvDesc->srvId = HSE_SRV_ID_IMPORT_KEY;

    /* Caller has pre-filled all fields; patch in the missing parameters */
    import_key_srv->pKeyInfo         = (HOST_ADDR) key_info;
    import_key_srv->targetKeyHandle  = *target_key_handle;
    pHseSrvDesc->hseSrv.importKeyReq = *import_key_srv;

    hseSrvResponse = HSE_Send(muIf, muChannelIdx, gSyncTxOption, pHseSrvDesc);
    if (HSE_SRV_RSP_OK != hseSrvResponse) {
        (void) HKF_FreeKeySlot(target_key_handle);
    }
exit:
    return ele_hseb_to_psa_status(hseSrvResponse);
}

static psa_status_t hseb_import_symmetric_key(const psa_key_attributes_t *attributes,
                                              const uint8_t *data,
                                              size_t data_length,
                                              uint8_t *key_buffer,
                                              size_t key_buffer_size,
                                              size_t *key_buffer_length,
                                              bool is_nvm)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t alg       = psa_get_key_algorithm(attributes);
    psa_key_type_t key_type   = psa_get_key_type(attributes);
    size_t key_bits           = psa_get_key_bits(attributes);
    psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);

    uint16_t hse_key_bits             = 0u;
    hseKeyType_t hse_key_type         = { 0 };
    hseKeyHandle_t target_key_handle  = { 0 };
    hseKeyFlags_t hse_key_flags       = { 0 };
    hseAesBlockModeMask_t cipher_mask = { 0 };
    hseImportKeySrv_t import_key_srv  = { 0 };
    uint16_t hse_data_length          = 0u;
    hseKeyInfo_t key_info             = { 0 };

    status = translate_unstructured_key_parameters(key_bits, &hse_key_bits, key_type,
                                                   &hse_key_type, alg, &cipher_mask);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Map the key permissions */
    psa_to_hseb_key_usage(key_usage, &hse_key_flags);

    if (data_length > (size_t) UINT16_MAX) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    hse_data_length = (uint16_t) data_length;

    key_info.keyType                   = hse_key_type;
    key_info.keyBitLen                 = hse_key_bits;
    key_info.keyFlags                  = hse_key_flags;
    key_info.specific.aesBlockModeMask = cipher_mask; /* Zero for MACs */

    import_key_srv.pKey[2]                    = (HOST_ADDR) data;
    import_key_srv.keyLen[2]                  = hse_data_length;
    /* Plain (unencrypted) import - no cipher or auth container */
    import_key_srv.cipher.cipherKeyHandle     = HSE_INVALID_KEY_HANDLE;
    import_key_srv.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

    status = hseb_import_raw_key_req(&import_key_srv, &key_info, &target_key_handle, is_nvm);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    ele_hseb_write_key_handle_to_buffer(key_buffer, key_buffer_length,
                                        &target_key_handle);
    status = PSA_SUCCESS;
exit:
    return status;
}


static psa_status_t hseb_import_ecc_key(const psa_key_attributes_t *attributes,
                                        const uint8_t *data,
                                        size_t data_length,
                                        uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        size_t *key_buffer_length,
                                        bool is_nvm)
{
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type     = psa_get_key_type(attributes);
    psa_ecc_family_t ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
    size_t key_bits             = psa_get_key_bits(attributes);
    psa_key_usage_t key_usage   = psa_get_key_usage_flags(attributes);

    hseKeyHandle_t target_key_handle  = { 0 };
    hseImportKeySrv_t import_key_srv  = { 0 };
    uint16_t hse_data_length          = 0u;
    hseKeyInfo_t key_info             = { 0 };

    psa_to_hseb_key_usage(key_usage, &key_info.keyFlags);
    key_info.keyFlags |= HSE_KF_ACCESS_EXPORTABLE; /* Make sure pubkey is exportable */

    if (data_length > (size_t) UINT16_MAX) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    hse_data_length = (uint16_t) data_length;

    if (((PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family) ||
         (PSA_ECC_FAMILY_MONTGOMERY == ecc_family)) &&
        (255u == key_bits)) {
        /* For these two curves, PSA spec wants to use 255, HSE-B wants to use 256 */
        key_info.keyBitLen = 256u;
    } else {
        if (key_bits > (size_t) UINT16_MAX) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        key_info.keyBitLen = (uint16_t) key_bits;
    }

    status = psa_to_hseb_curve(attributes, &key_info.specific.eccCurveId);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    /* Plain (unencrypted) import - no cipher or auth container */
    import_key_srv.cipher.cipherKeyHandle     = HSE_INVALID_KEY_HANDLE;
    import_key_srv.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

    if (true == PSA_KEY_TYPE_IS_KEY_PAIR(key_type)) {
        key_info.keyType         = HSE_KEY_TYPE_ECC_PAIR;
        import_key_srv.pKey[0]   = NULL_HOST_ADDR;
        import_key_srv.keyLen[0] = 0u;
        import_key_srv.pKey[2]   = (HOST_ADDR) data;
        import_key_srv.keyLen[2] = hse_data_length;

        /* Keep only the relevant permissions, otherwise we cannot import */
        if (true == PSA_ECC_FAMILY_IS_WEIERSTRASS(ecc_family)) {
            key_info.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_VERIFY |
                                  HSE_KF_USAGE_SIGN | HSE_KF_USAGE_EXCHANGE);
        } else if (PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family) {
            key_info.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_VERIFY |
                                  HSE_KF_USAGE_SIGN);
        } else if (PSA_ECC_FAMILY_MONTGOMERY == ecc_family) {
            key_info.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_EXCHANGE);
        } else {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else { /* true == PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type) */
        key_info.keyType = HSE_KEY_TYPE_ECC_PUB;

        /* We need the correct format */
        if (true == PSA_ECC_FAMILY_IS_WEIERSTRASS(ecc_family)) {
            import_key_srv.keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_UNCOMPRESSED;
            import_key_srv.pKey[0]                = (HOST_ADDR) data;
            import_key_srv.keyLen[0]              = hse_data_length;

            /* Keep only the relevant permissions, otherwise we cannot import */
            key_info.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_VERIFY |
                                  HSE_KF_USAGE_EXCHANGE);
        } else if (PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family) {
            import_key_srv.keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
            import_key_srv.pKey[0]                = (HOST_ADDR) data;
            import_key_srv.keyLen[0]              = hse_data_length;

            /* Keep only the relevant permissions, otherwise we cannot import */
            key_info.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_VERIFY);
        } else if (PSA_ECC_FAMILY_MONTGOMERY == ecc_family) {
            import_key_srv.keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
            import_key_srv.pKey[0]                = (HOST_ADDR) data;
            import_key_srv.keyLen[0]              = hse_data_length;

            /* Keep only the relevant permissions, otherwise we cannot import */
            key_info.keyFlags &= (HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_EXCHANGE);
        } else {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    }

    status = hseb_import_raw_key_req(&import_key_srv, &key_info, &target_key_handle, is_nvm);
    if (PSA_SUCCESS == status) {
        ele_hseb_write_key_handle_to_buffer(key_buffer, key_buffer_length,
                                            &target_key_handle);
    }
exit:
    return status;
}

psa_status_t ele_hseb_opaque_import_key(const psa_key_attributes_t *attributes,
                                        const uint8_t *data,
                                        size_t data_length,
                                        uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        size_t *key_buffer_length,
                                        size_t *bits)
{
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type     = psa_get_key_type(attributes);
    psa_key_lifetime_t lifetime = psa_get_key_lifetime(attributes);
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
    bool is_nvm                 = false;

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (PSA_KEY_LOCATION_ELE_HSEB == location) {
        /* Set the NVM flag if the key is persistent */
        is_nvm = !PSA_KEY_LIFETIME_IS_VOLATILE(lifetime);

        if (true == PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type)) {
            status = hseb_import_symmetric_key(attributes, data, data_length,
                                               key_buffer, key_buffer_size,
                                               key_buffer_length,
                                               is_nvm);
        } else if (true == PSA_KEY_TYPE_IS_ECC(key_type)) {
            status = hseb_import_ecc_key(attributes, data, data_length, key_buffer,
                                         key_buffer_size, key_buffer_length,
                                         is_nvm);
        } else if ((true == PSA_KEY_TYPE_IS_RSA(key_type)) &&
                   (true == is_nvm)) {
            /* RSA keys must be NVM keys, fail otherwise; HSEB limitation */
            // TBA
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else {
        /* This can be opaque keys that are unsupported or LOCAL_STORAGE keys
         * that get deferred to PSA core import.
         */
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_opaque_export_public_key(const psa_key_attributes_t *attributes,
                                               const uint8_t *key_buffer,
                                               size_t key_buffer_size,
                                               uint8_t *data,
                                               size_t data_size,
                                               size_t *data_length)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t ele_hseb_opaque_destroy_key(const psa_key_attributes_t *attributes,
                                         uint8_t *key_buffer,
                                         size_t key_buffer_size)
{
    psa_status_t status            = PSA_ERROR_CORRUPTION_DETECTED;
    hseKeyHandle_t hseb_key_handle = { 0 };

    (void) attributes;

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    ele_hseb_read_key_handle_from_buffer(key_buffer, &hseb_key_handle);
    status = ele_hseb_delete_key(&hseb_key_handle, HSE_ERASE_NOT_USED);

    if (PSA_SUCCESS == status) {
        (void) memset(key_buffer, 0, key_buffer_size);
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}
