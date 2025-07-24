/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*
 *  Generic ASN.1 parsing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/** \file mcux_psa_ele_hseb_asymmetric_signature.c
 *
 * This file contains the implementation of the entry points associated to the
 * asymmetric signature capability as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_ele_hseb_init.h"
#include "mcux_psa_ele_hseb_asymmetric_signature.h"
#include "mcux_psa_ele_hseb_translate.h"
#include "mcux_psa_ele_hseb_key_management.h"

#include "hse_host_ecc.h"
#include "hse_host_sign.h"

/******************************************************************************

   START : COPIED AND MODIFIED SOME OF THE ASN1 PARSING FUNCTIONS FROM MBEDTLS

        Copied to prevent having to depend on the entire mbedtls stack.
        Modified to prevent symbol conflicts.

 ******************************************************************************/

/** Out of data when parsing an ASN1 data structure. */
#define HSEB_ERR_ASN1_OUT_OF_DATA                      -0x0060
/** ASN1 tag was of an unexpected value. */
#define HSEB_ERR_ASN1_UNEXPECTED_TAG                   -0x0062
/** Error when trying to determine the length or invalid length. */
#define HSEB_ERR_ASN1_INVALID_LENGTH                   -0x0064

/** Integer tag. */
#define HSEB_ASN1_INTEGER                 0x02
/** Sequence tag. */
#define HSEB_ASN1_SEQUENCE                0x10
/** Constructed bit mask. */
#define HSEB_ASN1_CONSTRUCTED             0x20

static int hseb_asn1_get_len(unsigned char **p,
                             const unsigned char *end,
                             size_t *len)
{
    if ((end - *p) < 1) {
        return HSEB_ERR_ASN1_OUT_OF_DATA;
    }

    if ((**p & 0x80) == 0) {
        *len = *(*p)++;
    } else {
        int n = (**p) & 0x7F;
        if (n == 0 || n > 4) {
            return HSEB_ERR_ASN1_INVALID_LENGTH;
        }
        if ((end - *p) <= n) {
            return HSEB_ERR_ASN1_OUT_OF_DATA;
        }
        *len = 0;
        (*p)++;
        while (n--) {
            *len = (*len << 8) | **p;
            (*p)++;
        }
    }

    if (*len > (size_t) (end - *p)) {
        return HSEB_ERR_ASN1_OUT_OF_DATA;
    }

    return 0;
}

static int hseb_asn1_get_tag(unsigned char **p,
                             const unsigned char *end,
                             size_t *len, int tag)
{
    if ((end - *p) < 1) {
        return HSEB_ERR_ASN1_OUT_OF_DATA;
    }

    if (**p != tag) {
        return HSEB_ERR_ASN1_UNEXPECTED_TAG;
    }

    (*p)++;

    return hseb_asn1_get_len(p, end, len);
}

/******************************************************************************

   END : COPIED AND MODIFIED SOME OF THE ASN1 PARSING FUNCTIONS FROM MBEDTLS

 ******************************************************************************/

static psa_status_t psa_to_hseb_curve(const psa_key_attributes_t *attributes,
                                      hseEccCurveId_t *curve_id)
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_type_t key_type     = psa_get_key_type(attributes);
    psa_ecc_family_t ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
    size_t key_bits             = psa_get_key_bits(attributes);

    *curve_id = HSE_EC_CURVE_NONE;

    if (PSA_ECC_FAMILY_SECP_R1 == ecc_family) {
        switch (key_bits) {
            case 256:
                *curve_id = HSE_EC_SEC_SECP256R1;
                break;
            case 384:
                *curve_id = HSE_EC_SEC_SECP384R1;
                break;
            case 521:
                *curve_id = HSE_EC_SEC_SECP521R1;
                break;
            default:
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
        }
    } else if (PSA_ECC_FAMILY_BRAINPOOL_P_R1 == ecc_family) {
        switch (key_bits) {
            case 256:
                *curve_id = HSE_EC_BRAINPOOL_BRAINPOOLP256R1;
                break;
            case 320:
                *curve_id = HSE_EC_BRAINPOOL_BRAINPOOLP320R1;
                break;
            case 384:
                *curve_id = HSE_EC_BRAINPOOL_BRAINPOOLP384R1;
                break;
            case 512:
                *curve_id = HSE_EC_BRAINPOOL_BRAINPOOLP512R1;
                break;
            default:
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
        }
    } else if (PSA_ECC_FAMILY_TWISTED_EDWARDS == ecc_family) {
        if (256 == key_bits) {
            *curve_id = HSE_EC_25519_ED25519;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (PSA_ECC_FAMILY_MONTGOMERY == ecc_family) {
        if (256 == key_bits) {
            *curve_id = HSE_EC_25519_CURVE25519;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

/* When calling this, the caller should already know that alg is
 * a non-determenistic ECDSA alg.
 */
static psa_status_t psa_to_hseb_ecdsa(psa_algorithm_t alg,
                                      hseSignScheme_t *sign_scheme)
{
    psa_status_t status = psa_to_ele_hseb_hash(alg,
                                               &sign_scheme->sch.ecdsa.hashAlgo);
    sign_scheme->signSch = HSE_SIGN_ECDSA;
    return status;
}

static psa_status_t setkey_rsa(const psa_key_attributes_t *attributes,
                               hseKeyHandle_t *key_handle,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size)
{
    psa_status_t status           = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status  = HSE_SRV_RSP_GENERAL_ERROR;
    const size_t key_bits         = psa_get_key_bits(attributes);
    const size_t key_bytes        = PSA_BITS_TO_BYTES(key_bits);
    const psa_key_type_t key_type = psa_get_key_type(attributes);
    uint8_t *p                    = (uint8_t *) key_buffer;
    const uint8_t *end            = p + key_buffer_size;
    size_t len                    = 0u;
    size_t e_length               = 0u;
    uint8_t *n                    = NULL;
    uint8_t *e                    = NULL;
    uint8_t *d                    = NULL;

    /* Parse the initial SEQUENCE tag */
    if (0 != hseb_asn1_get_tag(&p, end, &len,
                               HSEB_ASN1_CONSTRUCTED | HSEB_ASN1_SEQUENCE)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (true == PSA_KEY_TYPE_IS_KEY_PAIR(key_type)) {
        /* For reference, we need the following values from the keypair data
         * RSAPrivateKey ::= SEQUENCE {
         *      version             INTEGER,  -- must be 0
         * ==>> modulus             INTEGER,  -- n
         * ==>> publicExponent      INTEGER,  -- e
         * ==>> privateExponent     INTEGER,  -- d
         *      prime1              INTEGER,  -- p
         *      prime2              INTEGER,  -- q
         *      exponent1           INTEGER,  -- d mod (p-1)
         *      exponent2           INTEGER,  -- d mod (q-1)
         *      coefficient         INTEGER,  -- (inverse of q) mod p
         * }
         */

        /* Version not needed, but we check its presence */
        if (0 != hseb_asn1_get_tag(&p, end, &len, HSEB_ASN1_INTEGER)) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }

        /* If first Byte of encoded value is set to 0x00 and the next Byte
         * is (Byte & 0x80 != 0), it's to prevent interpreting the encoded value
         * as a negative integer (as per two's complement representation).
         * In that case we skip that first 0x00 Byte and continue as usual.
         * Else it's a valid 0x00 Byte that's part of the key, so we don't skip.
         */

        /* Skip version field and continue with modulus n */
        p += len;
        if (0 != hseb_asn1_get_tag(&p, end, &len, HSEB_ASN1_INTEGER)) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        if (*p == 0x00 && (*(p+1) & 0x80) != 0) {
            p++;
            len--;
        }
        if (len != key_bytes) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        n = p;

        /* Skip modulus n and continue with exponent e */
        p += len;
        if (0 != hseb_asn1_get_tag(&p, end, &len, HSEB_ASN1_INTEGER)) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        e_length = len;
        if (*p == 0x00 && (*(p+1) & 0x80) != 0) {
            p++;
            len--;
        }
        e = p;

        /* Skip exponent e and continue with exponent d */
        p += len;
        if (0 != hseb_asn1_get_tag(&p, end, &len, HSEB_ASN1_INTEGER)) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        if (*p == 0x00 && (*(p+1) & 0x80) != 0) {
            p++;
            len--;
        }
        if (len != key_bytes) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        d = p;

        /* RSA key pairs cannot be placed into RAM key catalogs, so we use
         * the NVM key catalog for this kind of key
         */
        hseb_status = LoadRsaPair(key_handle, true, key_bits, n,
                                  e_length, e, d);
    } else { /* Public Key */
             /* We need both parts of the public key.
              * RSAPublicKey ::= SEQUENCE {
              *     modulus            INTEGER,    -- n
              *     publicExponent     INTEGER  }  -- e
              */

        /* Get the modulus n */
        if (0 != hseb_asn1_get_tag(&p, end, &len, HSEB_ASN1_INTEGER)) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        if (*p == 0x00 && (*(p+1) & 0x80) != 0) {
            p++;
            len--;
        }
        if (len != key_bytes) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        n = p;

        /* Skip modulus n and continue with exponent e */
        p += len;
        if (0 != hseb_asn1_get_tag(&p, end, &len, HSEB_ASN1_INTEGER)) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
        }
        e_length = len;
        if (*p == 0x00 && (*(p+1) & 0x80) != 0) {
            p++;
            len--;
        }
        e = p;

        hseb_status = LoadRsaPublicKey(key_handle, false, key_bits, n,
                                       e_length, e);

    }
    status = ele_hseb_to_psa_status(hseb_status);

exit:
    return status;
}

static psa_status_t setkey_ecc(const psa_key_attributes_t *attributes,
                               hseKeyHandle_t *key_handle,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size)
{
    psa_status_t status          = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;
    psa_key_type_t key_type      = psa_get_key_type(attributes);
    size_t key_bit_length        = psa_get_key_bits(attributes);
    hseEccCurveId_t curve_id     = HSE_EC_CURVE_NONE;

    status = psa_to_hseb_curve(attributes, &curve_id);
    if (PSA_SUCCESS != status) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (true == PSA_KEY_TYPE_IS_KEY_PAIR(key_type)) {
        /* PSA represents key pairs only by the private key. We can import
         * the private ked and HSE will compute the public part
         */
        hseb_status = LoadEccPrivateKey(key_handle, false, curve_id,
                                        key_bit_length, key_buffer);
    } else { /* Public key */
        hseb_status = LoadEccUncompressedPublicKey(key_handle, false, curve_id,
                                                   key_bit_length, key_buffer);
    }

    status = ele_hseb_to_psa_status(hseb_status);
    return status;
}

static psa_status_t ecdsa_sign(const psa_key_attributes_t *attributes,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size,
                               psa_algorithm_t alg,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *signature,
                               size_t signature_size,
                               size_t *signature_length,
                               bool is_input_hashed)
{
    psa_status_t status                   = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status          = HSE_SRV_RSP_GENERAL_ERROR;
    hseSignScheme_t sign_scheme           = { 0 };
    hseKeyHandle_t key_handle             = { 0 };
    uint8_t r[PSA_SIGNATURE_MAX_SIZE / 2] = { 0u };
    size_t rlen                           = sizeof(r);
    uint8_t s[PSA_SIGNATURE_MAX_SIZE / 2] = { 0u };
    size_t slen                           = sizeof(s);

    status = psa_to_hseb_ecdsa(alg, &sign_scheme);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    status = setkey_ecc(attributes, &key_handle, key_buffer, key_buffer_size);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    hseb_status = EcdsaSign(key_handle, sign_scheme.sch.ecdsa.hashAlgo,
                            input_length, input, is_input_hashed,
                            HSE_SGT_OPTION_NONE, (uint32_t *) &rlen, r, (uint32_t *) &slen, s);
    status = ele_hseb_to_psa_status(hseb_status);

exit:
    if (PSA_SUCCESS != status) {
        *signature_length = 0u;
    } else {
        /* Copy the signature to the external buffer and set signature length */
        (void) memcpy(signature, r, rlen);
        (void) memcpy(signature + rlen, s, slen);
        *signature_length = rlen + slen;
    }

    (void) ele_hseb_delete_key(&key_handle, HSE_ERASE_NOT_USED);
    return status;
}

static psa_status_t ecdsa_verify(const psa_key_attributes_t *attributes,
                                 const uint8_t *key_buffer,
                                 size_t key_buffer_size,
                                 psa_algorithm_t alg,
                                 const uint8_t *input,
                                 size_t input_length,
                                 const uint8_t *signature,
                                 size_t signature_length,
                                 bool is_input_hashed)
{
    psa_status_t status          = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;
    hseSignScheme_t sign_scheme  = { 0 };
    hseKeyHandle_t key_handle    = { 0 };
    size_t rlen                  = signature_length / 2u;
    size_t slen                  = signature_length / 2u;
    const uint8_t *r             = signature;
    const uint8_t *s             = signature + rlen;

    if (2u * PSA_BITS_TO_BYTES(psa_get_key_bits(attributes)) != signature_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    status = psa_to_hseb_ecdsa(alg, &sign_scheme);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    status = setkey_ecc(attributes, &key_handle, key_buffer, key_buffer_size);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    hseb_status = EcdsaVerify(key_handle, sign_scheme.sch.ecdsa.hashAlgo,
                              input_length, input, is_input_hashed,
                              HSE_SGT_OPTION_NONE, (uint32_t *) &rlen, r, (uint32_t *) &slen, s);
    status = ele_hseb_to_psa_status(hseb_status);

exit:
    (void) ele_hseb_delete_key(&key_handle, HSE_ERASE_NOT_USED);
    return status;
}

static size_t get_salt_length(const psa_key_attributes_t *attributes,
                              psa_algorithm_t alg)
{
    /* PSA requires either saltlength == hashlength OR, if not possible,
     * largest possible salt length for given parameter combination.
     */
    if (psa_get_key_bits(attributes) == 1024u &&
        PSA_ALG_SHA_512 == PSA_ALG_GET_HASH(alg)) {
        return 62u;
    } else {
        return PSA_HASH_LENGTH(alg);
    }
}

static psa_status_t rsa_sign(const psa_key_attributes_t *attributes,
                             const uint8_t *key_buffer,
                             size_t key_buffer_size,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *signature,
                             size_t signature_size,
                             size_t *signature_length,
                             bool is_input_hashed)
{
    psa_status_t status          = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;
    hseKeyHandle_t key_handle    = { 0 };
    hseHashAlgo_t hseb_hash      = { 0 };
    size_t salt_length           = 0u;

    status = setkey_rsa(attributes, &key_handle, key_buffer, key_buffer_size);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    *signature_length = signature_size;

    if (true == PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
        if (PSA_ALG_RSA_PKCS1V15_SIGN_RAW == alg) {
            /* HSEB does not support a signature scheme without a specified
             * hash algorithm.
             */
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        } else {
            status = psa_to_ele_hseb_hash(alg, &hseb_hash);
            if (PSA_SUCCESS != status) {
                goto exit;
            }

            hseb_status = RsaPkcs1v15SignSrv(key_handle, hseb_hash,
                                             input_length, (uint8_t *) input,
                                             is_input_hashed,
                                             HSE_SGT_OPTION_NONE,
                                             (uint32_t *) signature_length, signature);
        }
    } else if (true == PSA_ALG_IS_RSA_PSS(alg)) {
        status = psa_to_ele_hseb_hash(alg, &hseb_hash);
        if (PSA_SUCCESS != status) {
            goto exit;
        }

        salt_length = get_salt_length(attributes, alg);

        hseb_status = RsaPssSignSrv(key_handle, salt_length, hseb_hash,
                                    input_length, input, is_input_hashed,
                                    HSE_SGT_OPTION_NONE,
                                    (uint32_t *) signature_length, signature);
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = ele_hseb_to_psa_status(hseb_status);

exit:
    (void) ele_hseb_delete_key(&key_handle, HSE_ERASE_NOT_USED);
    return status;
}

static psa_status_t rsa_verify(const psa_key_attributes_t *attributes,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size,
                               psa_algorithm_t alg,
                               const uint8_t *input,
                               size_t input_length,
                               const uint8_t *signature,
                               size_t signature_length,
                               bool is_input_hashed)
{
    psa_status_t status          = PSA_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t hseb_status = HSE_SRV_RSP_GENERAL_ERROR;
    hseKeyHandle_t key_handle    = { 0 };
    hseHashAlgo_t hseb_hash      = { 0 };
    size_t salt_length           = 0u;

    if (PSA_BITS_TO_BYTES(psa_get_key_bits(attributes)) != signature_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    status = setkey_rsa(attributes, &key_handle, key_buffer, key_buffer_size);
    if (PSA_SUCCESS != status) {
        goto exit;
    }

    if (true == PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
        if (PSA_ALG_RSA_PKCS1V15_SIGN_RAW == alg) {
            /* HSEB does not support a signature scheme without a specified
             * hash algorithm.
             */
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        } else {
            status = psa_to_ele_hseb_hash(alg, &hseb_hash);
            if (PSA_SUCCESS != status) {
                goto exit;
            }

            hseb_status = RsaPkcs1v15VerSrv(key_handle, hseb_hash, input_length,
                                            input, is_input_hashed,
                                            HSE_SGT_OPTION_NONE,
                                            (uint32_t *) &signature_length, signature);
        }
    } else if (true == PSA_ALG_IS_RSA_PSS(alg)) {
        status = psa_to_ele_hseb_hash(alg, &hseb_hash);
        if (PSA_SUCCESS != status) {
            goto exit;
        }

        salt_length = get_salt_length(attributes, alg);

        hseb_status = RsaPssVerSrv(key_handle, salt_length, hseb_hash,
                                   input_length, input, is_input_hashed,
                                   HSE_SGT_OPTION_NONE, (uint32_t *) &signature_length,
                                   signature);
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = ele_hseb_to_psa_status(hseb_status);


exit:
    (void) ele_hseb_delete_key(&key_handle, HSE_ERASE_NOT_USED);
    return status;
}

psa_status_t ele_hseb_transparent_sign_message(const psa_key_attributes_t *attributes,
                                               const uint8_t *key_buffer,
                                               size_t key_buffer_size,
                                               psa_algorithm_t alg,
                                               const uint8_t *input,
                                               size_t input_length,
                                               uint8_t *signature,
                                               size_t signature_size,
                                               size_t *signature_length)
{
    psa_status_t status     = PSA_ERROR_CORRUPTION_DETECTED;
    size_t output_size      = 0u;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits         = psa_get_key_bits(attributes);

    /* Check if correct alg. Per PSA spec, the PKCS1V15_SIGN_RAW variant may
     * only be used with psa_sign_hash() and psa_verify_hash() functions.
     */
    if (false == PSA_ALG_IS_SIGN_MESSAGE(alg) ||
        PSA_ALG_RSA_PKCS1V15_SIGN_RAW == alg) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == input || 0u == input_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == signature || NULL == signature_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    output_size = PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg);
    if (output_size > signature_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (true == PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (true == PSA_ALG_IS_ECDSA(alg) &&
            false == PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
            status = ecdsa_sign(attributes, key_buffer, key_buffer_size, alg,
                                input, input_length, signature, signature_size,
                                signature_length, false);
        } else if (true == PSA_ALG_IS_HASH_EDDSA(alg) ||
                   PSA_ALG_PURE_EDDSA == alg) {
            /* EdDSA / PureEdDSA to be supported once key import
             * for HSEB is supported */
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (true == PSA_KEY_TYPE_IS_RSA(key_type)) {
        if (true == PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
            true == PSA_ALG_IS_RSA_PSS(alg)) {
            status = rsa_sign(attributes, key_buffer, key_buffer_size, alg,
                              input, input_length, signature, signature_size,
                              signature_length, false);
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (PSA_SUCCESS != status) {
        *signature_length = 0u;
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_transparent_verify_message(const psa_key_attributes_t *attributes,
                                                 const uint8_t *key_buffer,
                                                 size_t key_buffer_size,
                                                 psa_algorithm_t alg,
                                                 const uint8_t *input,
                                                 size_t input_length,
                                                 const uint8_t *signature,
                                                 size_t signature_length)
{
    psa_status_t status     = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type(attributes);

    /* Check if correct alg. Per PSA spec, the PKCS1V15_SIGN_RAW variant may
     * only be used with psa_sign_hash() and psa_verify_hash() functions.
     */
    if (false == PSA_ALG_IS_SIGN_MESSAGE(alg) ||
        PSA_ALG_RSA_PKCS1V15_SIGN_RAW == alg) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == input || 0u == input_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == signature || 0u == signature_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (true == PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (true == PSA_ALG_IS_ECDSA(alg) &&
            false == PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
            status = ecdsa_verify(attributes, key_buffer, key_buffer_size, alg,
                                  input, input_length, signature,
                                  signature_length, false);
        } else if (true == PSA_ALG_IS_HASH_EDDSA(alg) ||
                   PSA_ALG_PURE_EDDSA == alg) {
            /* EdDSA / PureEdDSA to be supported once key import
             * for HSEB is supported */
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (true == PSA_KEY_TYPE_IS_RSA(key_type)) {
        if (true == PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
            true == PSA_ALG_IS_RSA_PSS(alg)) {
            status = rsa_verify(attributes, key_buffer, key_buffer_size, alg,
                                input, input_length, signature,
                                signature_length, false);
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_transparent_sign_hash(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *hash,
                                            size_t hash_length,
                                            uint8_t *signature,
                                            size_t signature_size,
                                            size_t *signature_length)
{
    psa_status_t status     = PSA_ERROR_CORRUPTION_DETECTED;
    size_t output_size      = 0u;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits         = psa_get_key_bits(attributes);

    /* Check if correct alg. Per PSA spec, the PURE_EDDSA variant may
     * only be used with psa_sign_message() and psa_verify_message() functions.
     */
    if (false == PSA_ALG_IS_SIGN_HASH(alg) ||
        PSA_ALG_PURE_EDDSA == alg) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == hash || 0u == hash_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == signature || NULL == signature_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    output_size = PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg);
    if (output_size > signature_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (true == PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (true == PSA_ALG_IS_ECDSA(alg) &&
            false == PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
            status = ecdsa_sign(attributes, key_buffer, key_buffer_size, alg,
                                hash, hash_length, signature, signature_size,
                                signature_length, true);
        } else if (true == PSA_ALG_IS_HASH_EDDSA(alg)) {
            /* EdDSA to be supported once key import for HSEB is supported */
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (true == PSA_KEY_TYPE_IS_RSA(key_type)) {
        /* ELE_HSEB RSA hash sign/ver API does not align with the PSA API spec.
         * Per HSE API reference:
         *    "For RSA schemes, this [the input length] must be the length
         *     of the original (not pre-hashed) input."
         * This contition is not met by the PSA API, as we only receive hashlen.
         */
        status = PSA_ERROR_NOT_SUPPORTED;
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (PSA_SUCCESS != status) {
        *signature_length = 0u;
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_hseb_transparent_verify_hash(const psa_key_attributes_t *attributes,
                                              const uint8_t *key_buffer,
                                              size_t key_buffer_size,
                                              psa_algorithm_t alg,
                                              const uint8_t *hash,
                                              size_t hash_length,
                                              const uint8_t *signature,
                                              size_t signature_length)
{
    psa_status_t status     = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type(attributes);

    /* Check if correct alg. Per PSA spec, the PURE_EDDSA variant may
     * only be used with psa_sign_message() and psa_verify_message() functions.
     */
    if (false == PSA_ALG_IS_SIGN_HASH(alg) ||
        PSA_ALG_PURE_EDDSA == alg) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (NULL == key_buffer || 0u == key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == hash || 0u == hash_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (NULL == signature || 0u == signature_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (true == PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (true == PSA_ALG_IS_ECDSA(alg) &&
            false == PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
            status = ecdsa_verify(attributes, key_buffer, key_buffer_size, alg,
                                  hash, hash_length, signature,
                                  signature_length, true);
        } else if (true == PSA_ALG_IS_HASH_EDDSA(alg)) {
            /* EdDSA to be supported once key import for HSEB is supported */
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (true == PSA_KEY_TYPE_IS_RSA(key_type)) {
        /* ELE_HSEB RSA hash sign/ver API does not align with the PSA API spec.
         * Per HSE API reference:
         *    "For RSA schemes, this [the input length] must be the length
         *     of the original (not pre-hashed) input."
         * This contition is not met by the PSA API, as we only receive hashlen.
         */
        status = PSA_ERROR_NOT_SUPPORTED;
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}
