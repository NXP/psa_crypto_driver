/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_s2xx_psa_opaque_mac.c
 *
 * This file contains the definition of the entry points associated to the
 * mac capability (single-part only, multi-part (not supported in ele)) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_s2xx_common_init.h"
#include "mcux_psa_s2xx_opaque_mac.h"
#include "mcux_psa_s2xx_key_locations.h"
#include "mcux_psa_s2xx_common_key_management.h"

/* Convert PSA Algorithm to ELE Algorithm, CMAC or HMAC with SHA256 */
static psa_status_t ele_psa_mac_alg_to_ele_mac_alg(psa_algorithm_t alg, sss_algorithm_t *ele_alg)
{
#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(alg) == PSA_ALG_CMAC)
    {
        *ele_alg = kAlgorithm_SSS_CMAC_AES;
        return PSA_SUCCESS;
    }
    else
#endif /* PSA_WANT_ALG_CMAC */
#if defined(PSA_WANT_ALG_HMAC)
        if (PSA_ALG_IS_HMAC(alg))
    {
        psa_status_t status = PSA_SUCCESS;

        /* EL2GO FW adds support for more hashes compared to base S2XX */
        switch (PSA_ALG_HMAC_GET_HASH(alg))
        {
#if defined(PSA_WANT_ALG_SHA_256)
            case PSA_ALG_SHA_256:
                *ele_alg = kAlgorithm_SSS_HMAC_SHA256;
                break;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(ELE_FEATURE_EXTENDED_HMAC)
#if defined(PSA_WANT_ALG_SHA_1)
            case PSA_ALG_SHA_1:
                *ele_alg = kAlgorithm_SSS_HMAC_SHA1;
                break;
#endif /* PSA_WANT_ALG_SHA_1 */
#if defined(PSA_WANT_ALG_SHA_224)
            case PSA_ALG_SHA_224:
                *ele_alg = kAlgorithm_SSS_HMAC_SHA224;
                break;
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_384)
            case PSA_ALG_SHA_384:
                *ele_alg = kAlgorithm_SSS_HMAC_SHA384;
                break;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
            case PSA_ALG_SHA_512:
                *ele_alg = kAlgorithm_SSS_HMAC_SHA512;
                break;
#endif /* PSA_WANT_ALG_SHA_512 */
#endif /* ELE_FEATURE_EXTENDED_HMAC */
            default:
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
        }

        return status;
    }
    else
#endif /* PSA_WANT_ALG_HMAC */
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t key_management(const psa_key_attributes_t *attributes,
                                   const uint8_t *key_buffer,
                                   size_t key_buffer_size,
                                   sss_sscp_object_t *sssKey)
{
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;

    /* Validate if the key is a blob */
    psa_status = ele_s2xx_validate_blob_attributes(attributes, key_buffer, key_buffer_size);
    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    /* Import the key */
    psa_status = ele_s2xx_import_key(attributes, key_buffer, key_buffer_size, sssKey);
    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    return PSA_SUCCESS;
}

static psa_status_t do_mac(const uint8_t *input, size_t input_length,
                           uint8_t *mac, size_t mac_size, size_t *mac_length,
                           sss_sscp_object_t *sssKey, sss_algorithm_t ele_alg)
{
    sss_sscp_mac_t ctx = {0};

    /* Init context for MAC*/
    if ((sss_sscp_mac_context_init(&ctx, &g_ele_ctx.sssSession, sssKey, ele_alg, kMode_SSS_Mac)) !=
        kStatus_SSS_Success)
    {
        (void)sss_sscp_key_object_free(sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        return PSA_ERROR_GENERIC_ERROR;
    }
    /* Call MAC one go*/
    if ((sss_sscp_mac_one_go(&ctx, (const uint8_t *)input, input_length, (uint8_t *)mac, &mac_size)) !=
        kStatus_SSS_Success)
    {
        (void)sss_sscp_mac_context_free(&ctx);
        (void)sss_sscp_key_object_free(sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        return PSA_ERROR_GENERIC_ERROR;
    }

    *mac_length = mac_size;

    /* Free context */
    if (sss_sscp_mac_context_free(&ctx) != kStatus_SSS_Success)
    {
        (void)sss_sscp_key_object_free(sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

psa_status_t ele_s2xx_opaque_mac_compute(const psa_key_attributes_t *attributes,
                                              const uint8_t *key_buffer,
                                              size_t key_buffer_size,
                                              psa_algorithm_t alg,
                                              const uint8_t *input,
                                              size_t input_length,
                                              uint8_t *mac,
                                              size_t mac_size,
                                              size_t *mac_length)
{
    psa_status_t status      = PSA_ERROR_CORRUPTION_DETECTED;
    sss_algorithm_t ele_alg  = 0;
    sss_sscp_object_t sssKey = {0};

    /* Get Algo fo ELE */
    status = ele_psa_mac_alg_to_ele_mac_alg(alg, &ele_alg);
    if (PSA_SUCCESS != status)
    {
        return status;
    }

    /* Validations */
    if (!key_buffer || !key_buffer_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!mac_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = key_management(attributes, key_buffer, key_buffer_size, &sssKey);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    status = do_mac(input, input_length, mac, mac_size, mac_length, &sssKey, ele_alg);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return status;
}
