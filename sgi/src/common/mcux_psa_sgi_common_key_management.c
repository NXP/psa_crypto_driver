/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file  mcux_psa_sgi_common_key_management.c
 * @brief Implementation of common SGI key management utilities.
 *
 * Provides sgi_create_key_descriptor() which populates a mcuxClKey_Descriptor_t
 * from PSA key attributes. Shared between the transparent, opaque, and PKC PSA crypto drivers.
 */

#include "mcux_psa_sgi_common_key_management.h"
#include "mcux_psa_sgi_common_init.h"

#include <mcuxClKey.h>
#include <mcuxClKey_Types.h>
#include <mcuxClKey_Functions.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClCipherModes_Sgi_Types.h>
#include <mcuxClAes.h>
#include <mcuxClEcc.h>
#include <mcuxClHmac.h>

/* =========================================================================
 * Internal: map PSA ECC key pair type + bits to mcuxClKey_TypeDescriptor_t
 * ========================================================================= */

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
static psa_status_t get_ecc_key_pair_type_descriptor(
    const psa_key_attributes_t *attributes,
    mcuxClKey_TypeDescriptor_t *out_type_desc)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_ecc_family_t ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
    size_t key_bits = psa_get_key_bits(attributes);

    if (PSA_ECC_FAMILY_SECP_R1 == ecc_family) {
        switch (key_bits) {
#if defined(PSA_WANT_ECC_SECP_R1_192)
            case 192:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp192r1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_224)
            case 224:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp224r1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_256)
            case 256:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp256r1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
            case 384:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp384r1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_521)
            case 521:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp521r1_Priv;
                break;
#endif
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (PSA_ECC_FAMILY_BRAINPOOL_P_R1 == ecc_family) {
        switch (key_bits) {
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
            case 256:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_brainpoolP256r1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
            case 384:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_brainpoolP384r1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
            case 512:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_brainpoolP512r1_Priv;
                break;
#endif
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
#if defined(MCUXCL_FEATURE_ECC_SECPK1_CURVES)
    } else if (PSA_ECC_FAMILY_SECP_K1 == ecc_family) {
        switch (key_bits) {
#if defined(PSA_WANT_ECC_SECP_K1_192)
            case 192:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp192k1_Priv;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_K1_256)
            case 256:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp256k1_Priv;
                break;
#endif
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
#endif /* MCUXCL_FEATURE_ECC_SECPK1_CURVES */
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC */

/* =========================================================================
 * Internal: map PSA ECC public key type + bits to mcuxClKey_TypeDescriptor_t
 * ========================================================================= */

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
static psa_status_t get_ecc_public_key_type_descriptor(
    const psa_key_attributes_t *attributes,
    mcuxClKey_TypeDescriptor_t *out_type_desc)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_ecc_family_t ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
    size_t key_bits = psa_get_key_bits(attributes);

    if (PSA_ECC_FAMILY_SECP_R1 == ecc_family) {
        switch (key_bits) {
#if defined(PSA_WANT_ECC_SECP_R1_192)
            case 192:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp192r1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_224)
            case 224:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp224r1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_256)
            case 256:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp256r1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
            case 384:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp384r1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_R1_521)
            case 521:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp521r1_Pub;
                break;
#endif
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (PSA_ECC_FAMILY_BRAINPOOL_P_R1 == ecc_family) {
        switch (key_bits) {
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
            case 256:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_brainpoolP256r1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
            case 384:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_brainpoolP384r1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
            case 512:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_brainpoolP512r1_Pub;
                break;
#endif
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
#if defined(MCUXCL_FEATURE_ECC_SECPK1_CURVES)
    } else if (PSA_ECC_FAMILY_SECP_K1 == ecc_family) {
        switch (key_bits) {
#if defined(PSA_WANT_ECC_SECP_K1_192)
            case 192:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp192k1_Pub;
                break;
#endif
#if defined(PSA_WANT_ECC_SECP_K1_256)
            case 256:
                *out_type_desc = mcuxClKey_TypeDescriptor_WeierECC_secp256k1_Pub;
                break;
#endif
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
#endif /* MCUXCL_FEATURE_ECC_SECPK1_CURVES */
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */

/* =========================================================================
 * Internal: map PSA key type + size to mcuxClKey_TypeDescriptor_t
 * ========================================================================= */

static psa_status_t get_key_type_descriptor(
    const psa_key_attributes_t *attributes,
    size_t key_buffer_size,
    mcuxClKey_TypeDescriptor_t *out_type_desc)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);

    switch (key_type) {
#if defined(PSA_WANT_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            switch (key_buffer_size) {
                case 16u:
                    *out_type_desc = mcuxClKey_TypeDescriptor_Aes128;
                    break;
                case 32u:
                    *out_type_desc = mcuxClKey_TypeDescriptor_Aes256;
                    break;
                default:
                    return PSA_ERROR_NOT_SUPPORTED;
            }
            break;
#endif /* PSA_WANT_KEY_TYPE_AES */

        case PSA_KEY_TYPE_RAW_DATA:
        {
            mcuxClKey_TypeDescriptor_t type = { 0u, (mcuxClKey_Size_t) key_buffer_size, NULL,
                                                NULL };
            *out_type_desc = type;
        }
        break;

        case PSA_KEY_TYPE_HMAC:
        {
            *out_type_desc = mcuxClKey_TypeDescriptor_Hmac_variableLength;
        }
        break;

        default:
            /* Check if it's an ECC key pair */
            if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
                return get_ecc_key_pair_type_descriptor(attributes, out_type_desc);
#else
                return PSA_ERROR_NOT_SUPPORTED;
#endif
            }
            /* Check if it's an ECC public key */
            else if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type)) {
#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
                return get_ecc_public_key_type_descriptor(attributes, out_type_desc);
#else
                return PSA_ERROR_NOT_SUPPORTED;
#endif
            } else {
                return PSA_ERROR_NOT_SUPPORTED;
            }
    }

    return PSA_SUCCESS;
}

/* =========================================================================
 * sgi_create_key_descriptor
 * ========================================================================= */

psa_status_t sgi_create_key_descriptor(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    mcuxClKey_Descriptor_t *out_key_descriptor)
{
    psa_status_t status;
    psa_key_location_t location;
    mcuxClKey_TypeDescriptor_t keyTypeDesc;

    if (out_key_descriptor == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

    /* Configure key data pointers */
    mcuxClKey_setKeyData(out_key_descriptor, (uint8_t *) key_buffer);
    mcuxClKey_setKeyContainerSize(out_key_descriptor, (uint32_t) key_buffer_size);
    mcuxClKey_setKeyContainerUsedSize(out_key_descriptor, (uint32_t) key_buffer_size);
    mcuxClKey_setAuxData(out_key_descriptor, (void *) attributes);
    mcuxClKey_setLinkedData(out_key_descriptor, NULL);
    mcuxClKey_setParentKey(out_key_descriptor, NULL);

    /* Configure load state based on key location */
    if (PSA_KEY_LOCATION_LOCAL_STORAGE == location) {
        /* LOCAL_STORAGE: key material is directly accessible in memory */
        mcuxClKey_setLoadedKeyData(out_key_descriptor, (uint32_t *) key_buffer);
        mcuxClKey_setLoadedKeyLength(out_key_descriptor, (uint32_t) key_buffer_size);
        mcuxClKey_setLoadedKeySlot(out_key_descriptor, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
        mcuxClKey_setLoadStatus(out_key_descriptor, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    } else {
        /* Opaque location: key data pointers are set, but load is deferred.
         * The caller or oracle is responsible for loading into coprocessor. */
        mcuxClKey_setLoadedKeyData(out_key_descriptor, (uint32_t *) key_buffer);
        mcuxClKey_setLoadedKeyLength(out_key_descriptor, (uint32_t) key_buffer_size);
        mcuxClKey_setLoadedKeySlot(out_key_descriptor, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
        mcuxClKey_setLoadStatus(out_key_descriptor, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    }

    /* Map PSA key type to SGI key type descriptor */
    status = get_key_type_descriptor(attributes, key_buffer_size, &keyTypeDesc);
    if (PSA_SUCCESS != status) {
        return status;
    }

    mcuxClKey_setTypeDescriptor(out_key_descriptor, keyTypeDesc);
    mcuxClKey_setEncodingType(out_key_descriptor, keyTypeDesc.plainEncoding);

    return PSA_SUCCESS;
}
