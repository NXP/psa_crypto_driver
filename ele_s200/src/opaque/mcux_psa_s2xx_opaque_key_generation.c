/*
 * Copyright 2022-2023, 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_s2xx_key_generation.c
 *
 * This file contains the implementation of the entry points associated to the
 * key generation (i.e. random generation and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_s2xx_init.h" /* ELE Crypto port layer */
#include "mcux_psa_s2xx_opaque_key_generation.h"
#include "mcux_psa_s2xx_key_locations.h"
#include "mcux_psa_s2xx_common_key_management.h"
#include "mcux_psa_s2xx_common_compute.h"

psa_status_t ele_s2xx_opaque_import_key(const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length, uint8_t *key_buffer,
    size_t key_buffer_size, size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;
    sss_sscp_object_t sssKey    = {0};
    sss_sscp_tunnel_t tunnelCtx = {0};
    uint32_t resultState        = 0u;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)))
    {
        if (true == (MCUXCLPSADRIVER_IS_S200_KEY_STORAGE(location)))
        {
            /* Validate blob in software and import to let S200 validate too */
            status = ele_s2xx_import_key(attributes, data, data_length, &sssKey);
            if (PSA_SUCCESS != status)
            {
                goto exit;
            }

            /* Store the blob as-is in the PSA keystore */
            if (key_buffer_size < data_length)
            {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }

            (void)memcpy(key_buffer, data, data_length);
            *key_buffer_length = data_length;

            status = PSA_SUCCESS;
        }
        else if (true == (MCUXCLPSADRIVER_IS_S200_DATA_STORAGE(location)))
        {
            /* Open the tunnel */
            if (sss_sscp_tunnel_context_init(&tunnelCtx, &g_ele_ctx.sssSession, kSSS_tunnel_type_EL2GO_Data) != kStatus_SSS_Success)
            {
                status = PSA_ERROR_GENERIC_ERROR;
                goto exit;
            }

            tunnelCtx.buffer     = key_buffer;
            tunnelCtx.bufferSize = key_buffer_size;

            /* Pass the blob */
            if (sss_sscp_tunnel(&tunnelCtx, (uint8_t *)data, data_length, &resultState) !=
                kStatus_SSS_Success)
            {
                (void)sss_sscp_tunnel_context_free(&tunnelCtx);
                status = PSA_ERROR_GENERIC_ERROR;
                goto exit;
            }

            /* Free the tunnel */
            if (sss_sscp_tunnel_context_free(&tunnelCtx) != kStatus_SSS_Success)
            {
                status = PSA_ERROR_GENERIC_ERROR;
                goto exit;
            }

            *key_buffer_length = tunnelCtx.bufferSize;

            status = PSA_SUCCESS;
        }
        else
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else
    {
        /* Transparent key location case */
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
    if (true == MCUXCLPSADRIVER_IS_S200_KEY_STORAGE(location))
    {
        /* We won't be keeping the EL2GO key in S200 keystore */
        (void)ele_s2xx_delete_key(&sssKey);
    }

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_s2xx_opaque_export_key(const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        uint8_t *data,
                                        size_t data_size,
                                        size_t *data_length)
{
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

    if (MCUXCLPSADRIVER_IS_S200_DATA_STORAGE(location))
    {
        /* At this point the data has already been retrieved from
         * persistent storage and no ELE calls are needed.
         */
        (void)memcpy(data, key_buffer, key_buffer_size);
        *data_length = key_buffer_size;
        status = PSA_SUCCESS;
    }
    else if (MCUXCLPSADRIVER_IS_S200_KEY_STORAGE(location))
    {
        if (((psa_key_usage_t)0u == psa_get_key_usage_flags(attributes)) &&
            (PSA_ALG_NONE == psa_get_key_algorithm(attributes)) &&
            (PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) == psa_get_key_type(attributes)))
        {
            /* Reuse public key export */
            status = ele_s2xx_opaque_export_public_key(attributes, key_buffer, key_buffer_size, data, data_size, data_length);
        }
        else
        {
            /* Nothing else supported */
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

psa_status_t ele_s2xx_opaque_export_public_key(const psa_key_attributes_t *attributes,
                                               const uint8_t *key_buffer,
                                               size_t key_buffer_size, uint8_t *data,
                                               size_t data_size, size_t *data_length)
{
    psa_status_t status      = PSA_ERROR_CORRUPTION_DETECTED;
    sss_sscp_object_t sssKey = {0};
    size_t data_bitlen       = 0u;

    if (false == PSA_KEY_TYPE_IS_ECC(psa_get_key_type(attributes)))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* For an opaque blob, we can't directly export, so we import the key,
     * let the S200 calculate/unwrap the public key and then we retrieve it.
     */
    status = ele_s2xx_import_key(attributes, key_buffer, key_buffer_size, &sssKey);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    *data_length = data_size - 1u;
    if (sss_sscp_key_store_get_key(&g_ele_ctx.keyStore, &sssKey,
                                   data + 1, data_length,
                                   &data_bitlen, kSSS_KeyPart_Public) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_HARDWARE_FAILURE;
        goto exit;
    }

    /* PSA expects 0x04 as the leading byte for uncompressed ECC public keys */
    *data        = 0x04u;
    *data_length = *data_length + 1u;

    status = PSA_SUCCESS;
exit:
    (void)ele_s2xx_delete_key(&sssKey);

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_s2xx_opaque_destroy_key(const psa_key_attributes_t *attributes,
                                         uint8_t *key_buffer,
                                         size_t key_buffer_size)
{
    /* At this time, we do not store any key in the S200 keystore beyond
     * the lifetime of any given API operation. This function has no effect
     * until such caching is implemented in some way.
     */
    return PSA_SUCCESS;
}

static psa_status_t ele_s2xx_get_key_buffer_size_from_key_data(const psa_key_attributes_t *attributes,
                                                               const uint8_t *data,
                                                               size_t data_length,
                                                               size_t *key_buffer_length)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;

    if (true == MCUXCLPSADRIVER_IS_S200_KEY_STORAGE(location) ||
        true == MCUXCLPSADRIVER_IS_S200_DATA_STORAGE(location) ||
        true == MCUXCLPSADRIVER_IS_S200_KEY_STORAGE_NON_EL2GO(location) )
    {
        *key_buffer_length = data_length;
        status             = PSA_SUCCESS;
    }
    else
    {
        // TBD if other locations are supported, add them
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

size_t ele_s2xx_opaque_size_function(const psa_key_attributes_t *attributes,
                                     const uint8_t *data,
                                     size_t data_length)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
                                      psa_get_key_lifetime(attributes));
    size_t key_buffer_size      = 0;
    if (false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)))
    {
        psa_status_t status = ele_s2xx_get_key_buffer_size_from_key_data(attributes,
                                                                         data,
                                                                         data_length,
                                                                         &key_buffer_size);
        if (PSA_SUCCESS != status)
        {
            key_buffer_size = 0;
        }
    }
    return key_buffer_size;
}

size_t ele_s2xx_opaque_get_key_buffer_size(const psa_key_attributes_t *attributes)
{
    size_t bits                 = psa_get_key_bits(attributes);
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));
    psa_key_type_t type         = psa_get_key_type(attributes);
    size_t key_buffer_size      = 0u;

    if (PSA_KEY_LOCATION_S200_KEY_STORAGE_NON_EL2GO == location)
    {
        if (true == PSA_KEY_TYPE_IS_ECC(type))
        {
            /* If it's ECC, then it's a key pair, as PSA does not allow
             * generating only public parts of keys AND for S200 die-unique keys
             * we blob the full keypair (vs PSA's way of only storing the
             * private keypart for ECC key pairs).
             */
            key_buffer_size = ele_s2xx_get_ecc_keypair_size(bits);
        }
        else
        {
            key_buffer_size = PSA_BITS_TO_BYTES(bits);
        }

        key_buffer_size += S200_BLOB_OVERHEAD;
    }
    else
    {
        key_buffer_size = 0u;
    }

    return key_buffer_size;
}

static psa_status_t translate_psa_key_agreement_to_ele_key_agreement(psa_algorithm_t alg,
                                                                     sss_algorithm_t *ele_alg)
{
    psa_status_t status = PSA_SUCCESS;

    switch (alg)
    {
        case PSA_ALG_ECDH:
            *ele_alg = kAlgorithm_SSS_ECDH;
            break;
        case ALG_S200_ECDH_CKDF:
            *ele_alg = kAlgorithm_SSS_E2E_BLOB;
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    return status;
}

static psa_status_t init_shared_secret_key_object(sss_sscp_object_t *sssKey_shared,
                                                  size_t allocation_size)
{
    psa_status_t status                    = PSA_ERROR_CORRUPTION_DETECTED;
    sss_sscp_key_property_t key_properties = {0};

    if (sss_sscp_key_object_init(sssKey_shared, &g_ele_ctx.keyStore) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_HARDWARE_FAILURE;
        goto exit;
    }

    /* Disable all operations for this key, except for plain read */
    key_properties = kSSS_KeyProp_NoImportExport | kSSS_KeyProp_NoPlainWrite |
                     kSSS_KeyProp_NoVerify       | kSSS_KeyProp_NoSign;
    if (sss_sscp_key_object_allocate_handle(sssKey_shared, 0u,
                                            kSSS_KeyPart_Default, kSSS_CipherType_SYMMETRIC,
                                            allocation_size,
                                            key_properties) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_HARDWARE_FAILURE;
        goto exit;
    }

    status = PSA_SUCCESS;
exit:
    /* Not freeing shared key object, leaving it to the caller */

    return status;
}

psa_status_t ele_s2xx_opaque_key_agreement(const psa_key_attributes_t *attributes,
                                           const uint8_t *key_buffer,
                                           size_t key_buffer_size,
                                           psa_algorithm_t alg,
                                           const uint8_t *peer_key,
                                           size_t peer_key_length,
                                           uint8_t *shared_secret,
                                           size_t shared_secret_size,
                                           size_t *shared_secret_length)
{
    psa_status_t status             = PSA_ERROR_CORRUPTION_DETECTED;
    sss_sscp_object_t sssKey        = {0};
    sss_sscp_object_t sssKey_peer   = {0};
    sss_sscp_object_t sssKey_shared = {0};
    sss_algorithm_t ele_alg         = {0};
    size_t bits                     = psa_get_key_bits(attributes);

    /* Only ECC keys for key agreement are supported by S200 */
    if (false == PSA_KEY_TYPE_IS_ECC(psa_get_key_type(attributes)))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Check if alg is supported by S200 */
    status = translate_psa_key_agreement_to_ele_key_agreement(alg, &ele_alg);
    if (PSA_SUCCESS != status)
    {
        return status;
    }

    /* Check curve family support */
    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) &&
        psa_get_key_type(attributes) != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Validations for supported key sizes for the given ECC family / algorithm
     * ECC Families : 224-521 for ECC_FAMILY_SECP_R1,
     *                256     for ECC_FAMILY_MONTGOMERY
     * Algorithms   : 224-521 for ALG_ECDH
     *                256     for ALG_S200_ECDH_CKDF
     */
    status = PSA_ERROR_NOT_SUPPORTED;
    switch (bits)
    {
        case 256u:
            /* 256 supported by all curves and algorithms validated in previous steps */
            status = PSA_SUCCESS;
            break;
        case 224u:
        case 384u:
        case 521u:
            /* 224, 384, and 521 supported only with (ECC_FAMILY_SECP_R1 && ALG_ECDH) */
            if ((PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) == psa_get_key_type(attributes)) &&
                (PSA_ALG_ECDH == alg))
            {
                status = PSA_SUCCESS;
            }
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }
    if (PSA_SUCCESS != status)
    {
        return status;
    }

    if (NULL == key_buffer || 0u == key_buffer_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == peer_key || 0u == peer_key_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Load our key pair */
    status = ele_s2xx_import_key(attributes, key_buffer, key_buffer_size, &sssKey);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    /* Load the peer key - peer key buffer and size shifted by 1 element,
     * since S200 expects no leading 0x04 Byte
     */
    status = ele_s2xx_set_key(&sssKey_peer, 0u, (peer_key + 1), (peer_key_length - 1u), kSSS_KeyPart_Public,
                              kSSS_CipherType_EC_NIST_P, kSSS_KeyProp_CryptoAlgo_KDF,
                              PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(bits),
                              bits);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    /* Initialize the shared secret key object */
    status = init_shared_secret_key_object(&sssKey_shared, PSA_BITS_TO_BYTES(bits));
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    /* Do the key agreement, get the shared secret and set the output size */
    status = ele_s2xx_common_key_agreement(&sssKey, &sssKey_peer, &sssKey_shared,
                                           shared_secret, shared_secret_size, shared_secret_length,
                                           ele_alg);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

exit:
    /* Delete keys from the S200 keystore */
    (void)ele_s2xx_delete_key(&sssKey_peer);
    (void)ele_s2xx_delete_key(&sssKey_shared);
    (void)ele_s2xx_delete_key(&sssKey);

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}


psa_status_t ele_s2xx_opaque_generate_key(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          size_t *key_buffer_length)
{
    psa_status_t status           = PSA_SUCCESS;
    psa_key_type_t type           = psa_get_key_type(attributes);
    psa_ecc_family_t ecc_family   = PSA_KEY_TYPE_ECC_GET_FAMILY(type);
    size_t bits                   = psa_get_key_bits(attributes);
    psa_key_lifetime_t lifetime   = psa_get_key_lifetime(attributes);
    psa_key_location_t location   = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
    sss_sscp_object_t sssKey      = {0u};
    sss_key_part_t key_part       = {0u};
    sss_cipher_type_t cipher_type = {0u};
    size_t allocation_size        = 0u;

    // TBD is this OK?
    /* We'll be permissive and leave the key usage checks to PSA */
    uint32_t keyprops = 0x1fu;

    /* For opaque keygen we support non-EL2GO opaque keys */
    if (false == MCUXCLPSADRIVER_IS_S200_KEY_STORAGE_NON_EL2GO(location))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (true == PSA_KEY_TYPE_IS_ASYMMETRIC(type))
    {
        // ASYMMETRIC
        if (false == PSA_KEY_TYPE_IS_ECC(type) && false == PSA_KEY_TYPE_IS_DH(type))
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        /* Public part mustn't be generated. For keypair, we can store the whole
         * keypair blob instead of just the private part (PSA quirk with ECC
         * keys) and skip the export_public_key step. This enables PSA support
         * for EdDSA with opaque keys on S200.
         */
        key_part = kSSS_KeyPart_Pair;

        switch (ecc_family)
        {
            case PSA_ECC_FAMILY_SECP_R1:
                cipher_type = kSSS_CipherType_EC_NIST_P;
                break;
            case PSA_ECC_FAMILY_MONTGOMERY:
                cipher_type = kSSS_CipherType_EC_MONTGOMERY;
                break;
            case PSA_ECC_FAMILY_TWISTED_EDWARDS:
                cipher_type = kSSS_CipherType_EC_TWISTED_ED;
                break;
#if defined(ELE200_EXTENDED_FEATURES)
            case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
                cipher_type = kSSS_CipherType_EC_BRAINPOOL_R1;
                break;
#endif /* ELE200_EXTENDED_FEATURES */
            default:
                cipher_type = kSSS_CipherType_NONE;
                break;
        }
        if (kSSS_CipherType_NONE == cipher_type)
        {
            return  PSA_ERROR_NOT_SUPPORTED;
        }

        /* The S200 expects 256 bitlen for Ed25519, so we update the bits
         * variable for the later call to sss_sscp_key_store_generate_key().
         */
        if ((PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family ||
             PSA_ECC_FAMILY_MONTGOMERY == ecc_family) &&
            (true == IS_VALID_ED25519_BITLENGTH(bits)))
        {
            bits = 256u;
        }

        allocation_size = ele_s2xx_get_ecc_keypair_size(bits);
    }
    else
    {
        // UNSTRUCTURED / SYMMETRIC
        if (PSA_KEY_TYPE_AES != type && PSA_KEY_TYPE_HMAC != type)
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        key_part        = kSSS_KeyPart_Default;
        cipher_type     = kSSS_CipherType_SYMMETRIC;
        allocation_size = PSA_BITS_TO_BYTES(bits);
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if ((sss_sscp_key_object_init(&sssKey, &g_ele_ctx.keyStore)) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if ((sss_sscp_key_object_allocate_handle(&sssKey, 0u, /* key id */
                                             key_part, cipher_type, allocation_size,
                                             keyprops)) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (sss_sscp_key_store_generate_key(&g_ele_ctx.keyStore, &sssKey, bits, NULL) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    *key_buffer_length = key_buffer_size;
    if ((sss_sscp_key_store_export_key(&g_ele_ctx.keyStore, &sssKey, key_buffer, key_buffer_length,
                                       kSSS_blobType_ELKE_blob)) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

exit:
    (void)ele_s2xx_delete_key(&sssKey);

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

/** @} */ // end of psa_key_generation
