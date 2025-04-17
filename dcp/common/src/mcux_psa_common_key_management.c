/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "psa/crypto.h"
#include "psa_crypto_rsa.h"
#include "psa_crypto_ecp.h"

#include "mbedtls/asn1write.h"
#include "mbedtls/platform.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/psa_util.h"

#include "mcux_psa_common_key_management.h"

#define MCUX_RSA_PRIMES_CUSTOM

#ifdef MCUX_RSA_PRIMES_CUSTOM
static const uint8_t s_primeP2048[2048 >> 4] = {
    0xd9, 0xc6, 0x76, 0x41, 0xc2, 0x2c, 0x22, 0x28, 0x39, 0x38, 0xb1, 0xc9, 0xec, 0x14, 0x47, 0xc7, 0x1a, 0xf2, 0x55,
    0x0d, 0x70, 0x6b, 0xf3, 0xe4, 0xf9, 0xdd, 0xb9, 0xeb, 0x27, 0x54, 0xa1, 0x76, 0xcc, 0xc6, 0x96, 0xe8, 0xad, 0xe9,
    0xd7, 0x8e, 0xf5, 0x63, 0x04, 0x0e, 0x70, 0x7b, 0xf1, 0x00, 0x80, 0x45, 0x29, 0xb3, 0x30, 0x87, 0x06, 0x65, 0xd2,
    0xd3, 0xe1, 0x9e, 0xd7, 0x23, 0x08, 0x0e, 0x76, 0xbb, 0x8f, 0x64, 0x31, 0x43, 0xb1, 0xb9, 0x37, 0xe0, 0x63, 0xb7,
    0x00, 0x4f, 0x64, 0x09, 0xd3, 0x3c, 0xbd, 0xb2, 0x49, 0xef, 0x85, 0xb9, 0x97, 0xdd, 0x7b, 0x2b, 0xe3, 0xa4, 0x67,
    0x54, 0x9b, 0xed, 0x92, 0x86, 0x0e, 0x00, 0xd2, 0x8e, 0x87, 0xae, 0xfa, 0xd1, 0x57, 0x8f, 0x35, 0x66, 0x57, 0x55,
    0x73, 0xf9, 0x3d, 0x97, 0x6c, 0x7c, 0x8c, 0xc7, 0x4b, 0xf2, 0x88, 0x21, 0x6f, 0x9f};
static const uint8_t s_primeQ2048[2048 >> 4] = {
    0xb7, 0x11, 0xf5, 0x90, 0x23, 0xf7, 0x8f, 0xb9, 0x9a, 0x00, 0xc7, 0x75, 0x15, 0x61, 0x9d, 0x05, 0x71, 0x96, 0x29,
    0xd7, 0x7c, 0x0a, 0x72, 0xe6, 0x0a, 0x71, 0xaa, 0xac, 0x0a, 0xa5, 0xe2, 0x08, 0xc6, 0x76, 0x3b, 0xe8, 0x62, 0x54,
    0x53, 0x39, 0x76, 0x34, 0xbd, 0xf1, 0x1d, 0x81, 0x11, 0xa7, 0x76, 0x88, 0x99, 0xa9, 0x4b, 0x9f, 0x42, 0x72, 0x4a,
    0x11, 0x7d, 0xc1, 0xd6, 0xce, 0xbb, 0xec, 0x2c, 0x68, 0x5e, 0x21, 0x58, 0xdc, 0x4c, 0x88, 0x0b, 0xa2, 0xb5, 0x82,
    0x6a, 0x3a, 0x13, 0x5b, 0xf7, 0xff, 0xa0, 0x5a, 0x8c, 0x1a, 0x38, 0x4b, 0x55, 0x39, 0x70, 0xb0, 0xf4, 0xc4, 0x43,
    0x53, 0x13, 0xe5, 0xda, 0x0c, 0xd5, 0x18, 0x3d, 0xd5, 0x91, 0xb0, 0xd5, 0x71, 0x43, 0xaa, 0x44, 0x3e, 0x00, 0x7a,
    0x4c, 0xae, 0x00, 0x48, 0x62, 0xab, 0x55, 0x86, 0x65, 0xad, 0xeb, 0x10, 0xf1, 0x2b};
static const uint8_t s_primeP3072[3072 >> 4] = {
    0xeb, 0xdc, 0x88, 0xf8, 0xbd, 0x1d, 0x1a, 0x6b, 0x5c, 0x0f, 0x8d, 0x59, 0x4a, 0x7a, 0x71, 0x1e, 0xc2, 0x0a,
    0xd3, 0x3d, 0x84, 0x36, 0x45, 0x93, 0x79, 0xd7, 0x39, 0xaa, 0x49, 0x9b, 0x71, 0xd3, 0xf5, 0xd2, 0xdb, 0x0f,
    0xe7, 0x09, 0x87, 0xd9, 0x9f, 0x25, 0x0b, 0xda, 0xcd, 0xa8, 0xbf, 0x9f, 0x10, 0xa0, 0x73, 0xf0, 0xac, 0xa7,
    0x3e, 0x32, 0x1f, 0x5a, 0x5d, 0x12, 0x5a, 0xa3, 0x48, 0x66, 0x64, 0xc8, 0x18, 0xa8, 0xe4, 0xf6, 0x49, 0x9d,
    0xc1, 0xcf, 0x62, 0x56, 0x5a, 0x89, 0xd3, 0x27, 0xc1, 0xd1, 0x80, 0xce, 0xca, 0xe0, 0xdc, 0x76, 0x1a, 0x70,
    0x23, 0x74, 0x0a, 0xd6, 0x34, 0xdf, 0xc0, 0x5b, 0xae, 0x12, 0x1e, 0x91, 0x9f, 0x7d, 0xe4, 0xa0, 0x73, 0xdc,
    0x67, 0x36, 0xa4, 0x51, 0x1e, 0x32, 0x25, 0x38, 0xb5, 0x8d, 0xc9, 0xa9, 0xab, 0xf8, 0xd8, 0x89, 0xfb, 0x80,
    0x99, 0xea, 0x0b, 0x79, 0xcc, 0xc8, 0xdc, 0x11, 0x85, 0xfd, 0x3f, 0xde, 0xdf, 0x8f, 0x51, 0x17, 0xb9, 0x28,
    0xd9, 0x2d, 0x55, 0x36, 0x80, 0x30, 0x58, 0x76, 0xf5, 0x35, 0x7a, 0x99, 0x89, 0x53, 0xe3, 0xbd, 0x16, 0xd1,
    0xe9, 0xdb, 0x18, 0xb1, 0x6a, 0xda, 0x7f, 0x4a, 0x88, 0xe5, 0x22, 0xf2, 0x16, 0x3a, 0x91, 0xcc, 0x6a, 0xd9,
    0x0d, 0x61, 0x20, 0x55, 0xd8, 0x4f, 0x97, 0x99, 0x07, 0x68, 0xc1, 0xd9};
static const uint8_t s_primeQ3072[3072 >> 4] = {
    0xdf, 0xdd, 0xe7, 0x89, 0xa3, 0x66, 0x71, 0x5d, 0x09, 0x42, 0x63, 0x42, 0x6f, 0x6a, 0x02, 0x87, 0x37, 0xd0,
    0xd4, 0x8f, 0xd3, 0xf0, 0xe7, 0x0c, 0x73, 0x2e, 0x26, 0x98, 0x0e, 0x64, 0x6a, 0x6a, 0x51, 0x1d, 0x9b, 0x0a,
    0x22, 0xf0, 0x27, 0x6a, 0x85, 0x11, 0x71, 0x45, 0xce, 0xf2, 0x97, 0x73, 0xfb, 0xba, 0xab, 0xb5, 0x65, 0x96,
    0x01, 0x80, 0x5b, 0xa2, 0xb6, 0x2a, 0xd5, 0x6e, 0xa2, 0x3b, 0x13, 0xcd, 0x28, 0xbd, 0x02, 0x9d, 0xd9, 0x5b,
    0x75, 0x06, 0xab, 0x8b, 0x23, 0xf0, 0xbb, 0x45, 0xdd, 0x05, 0xd1, 0xf0, 0x96, 0x36, 0x6c, 0x85, 0x3c, 0x46,
    0xb7, 0x2c, 0x11, 0x6e, 0x9b, 0xb2, 0x46, 0xd9, 0x78, 0x0e, 0x38, 0x1e, 0x59, 0x97, 0xd0, 0x19, 0xfe, 0x76,
    0x2a, 0x06, 0x0d, 0x0f, 0xa9, 0xba, 0x24, 0x72, 0x8c, 0x35, 0xc6, 0x98, 0xd3, 0xb8, 0xd9, 0x0d, 0xd9, 0x39,
    0xcb, 0x14, 0x25, 0x37, 0x0e, 0x09, 0xae, 0x1f, 0x96, 0x3b, 0xbf, 0xe0, 0x9d, 0xc4, 0x7b, 0xbc, 0x16, 0x96,
    0x50, 0xb3, 0xa3, 0xba, 0x50, 0x4c, 0x1e, 0x72, 0x24, 0xc1, 0x4c, 0x83, 0x39, 0xfe, 0xcb, 0xc9, 0x00, 0xb9,
    0x5d, 0x66, 0x66, 0x97, 0x35, 0x1d, 0xb5, 0x33, 0x7e, 0x9f, 0xe9, 0xc3, 0xb9, 0xd8, 0xa5, 0x21, 0xf2, 0xa2,
    0xc5, 0xb2, 0xd2, 0x71, 0xcf, 0x2f, 0x3e, 0x62, 0xf4, 0xb5, 0x57, 0x15};
static const uint8_t s_primeP4096[4096 >> 4] = {
    0x8b, 0xcf, 0x06, 0xb9, 0xb5, 0xfd, 0x6b, 0x40, 0xc2, 0xf1, 0x37, 0xa7, 0x2e, 0x5c, 0x7d, 0x6e, 0x17, 0x9d, 0x04,
    0x74, 0x19, 0x34, 0x62, 0x04, 0xf4, 0xef, 0x0a, 0xcf, 0x23, 0xd4, 0x21, 0x70, 0x7c, 0x5d, 0xd9, 0xe4, 0xa2, 0x7f,
    0xd9, 0x19, 0xe4, 0x9a, 0xf2, 0x90, 0x5c, 0xa7, 0x86, 0x0c, 0x0e, 0xe4, 0x03, 0x3e, 0xd7, 0xd5, 0x8b, 0xec, 0x50,
    0xa5, 0x5f, 0x73, 0xa8, 0x89, 0xb9, 0xd2, 0x2c, 0xf4, 0xb3, 0xaa, 0xef, 0xf7, 0xb9, 0xd4, 0xe2, 0xba, 0xcf, 0xde,
    0xc8, 0x87, 0x56, 0xd2, 0xe1, 0xfd, 0x95, 0x54, 0x95, 0x66, 0x19, 0x51, 0xbc, 0xb9, 0xe4, 0x8c, 0x1a, 0xbb, 0x61,
    0xda, 0xb4, 0xb2, 0x26, 0xa7, 0x95, 0xc6, 0x5f, 0x56, 0x0f, 0x9a, 0x7e, 0x73, 0x45, 0xa6, 0xa1, 0x79, 0xd9, 0x48,
    0x3a, 0x65, 0x26, 0x6d, 0x84, 0x94, 0xe3, 0xca, 0x6b, 0xf7, 0x1f, 0x12, 0xee, 0xaa, 0x4f, 0x7b, 0x4f, 0x19, 0xda,
    0x54, 0x1f, 0x57, 0x39, 0xa7, 0xb7, 0x92, 0xeb, 0x48, 0x9f, 0x4c, 0x9d, 0x87, 0xfd, 0xc5, 0xb1, 0xfa, 0x52, 0x57,
    0xe1, 0x15, 0x8c, 0xf4, 0xb6, 0x0b, 0xc1, 0x8d, 0x3a, 0x06, 0x59, 0x51, 0x30, 0xed, 0x6e, 0xee, 0xc0, 0x93, 0xcf,
    0x2e, 0x77, 0xc4, 0xc9, 0x33, 0xb8, 0xf5, 0x50, 0x59, 0x8a, 0xf7, 0x1e, 0x40, 0x81, 0xbf, 0x0b, 0xa9, 0xbe, 0x44,
    0x8e, 0x58, 0xf9, 0x47, 0x0f, 0xe0, 0x1e, 0xfd, 0x5a, 0xf6, 0x1d, 0x3a, 0xd9, 0x74, 0x4d, 0xfd, 0xc0, 0x97, 0x57,
    0xa9, 0x5c, 0x63, 0xa9, 0x59, 0xbd, 0xb1, 0x58, 0xa9, 0xe9, 0x33, 0x83, 0x5c, 0xf7, 0xee, 0x8a, 0xec, 0xba, 0x58,
    0xd1, 0x98, 0xe1, 0x7c, 0x16, 0x00, 0x8d, 0x6b, 0x17, 0xdd, 0xfd, 0xd6, 0xa8, 0xd8, 0x4e, 0x47, 0xdb, 0x37, 0x36,
    0x85, 0x65, 0x01, 0x4c, 0xb5, 0x62, 0x61, 0xeb, 0x37};
static const uint8_t s_primeQ4096[4096 >> 4] = {
    0x8a, 0xb7, 0x75, 0xf6, 0x0e, 0xb7, 0x0a, 0x24, 0x66, 0xbc, 0xf7, 0x97, 0x88, 0x2b, 0xb5, 0x83, 0x79, 0x21, 0xe5,
    0x97, 0x60, 0xb4, 0xe9, 0x73, 0xa7, 0xdc, 0x2d, 0xc9, 0x6e, 0x1a, 0x48, 0x93, 0x6f, 0xf0, 0xab, 0xe0, 0x76, 0xac,
    0x15, 0x67, 0xed, 0xf0, 0x6e, 0x98, 0x55, 0x2a, 0x49, 0x0e, 0x07, 0xcf, 0xff, 0xe5, 0x77, 0xfc, 0x34, 0xed, 0xfa,
    0x42, 0x6d, 0xad, 0x6e, 0x24, 0x96, 0x79, 0x04, 0x68, 0xb8, 0xf0, 0x94, 0x88, 0x96, 0x3e, 0x3c, 0xbe, 0x41, 0x49,
    0x6a, 0x2b, 0xb2, 0x78, 0xc9, 0xbf, 0x4b, 0x49, 0x37, 0x4b, 0xf9, 0x88, 0x6a, 0x84, 0xd1, 0xd0, 0x0b, 0x82, 0xef,
    0xac, 0x20, 0xb7, 0xd4, 0x5b, 0x32, 0x09, 0xda, 0xb7, 0xc6, 0xc8, 0x51, 0xf1, 0x47, 0x4d, 0xcd, 0xef, 0xd7, 0xa8,
    0xa5, 0xbd, 0x0f, 0x3b, 0x62, 0x7a, 0x3b, 0x8e, 0x70, 0xbf, 0x31, 0x82, 0x4a, 0x74, 0xd9, 0x2d, 0xec, 0x07, 0x5f,
    0x89, 0xc8, 0x7b, 0x76, 0x63, 0x97, 0x27, 0x6c, 0xd5, 0x5d, 0x6c, 0xea, 0x0c, 0x12, 0x35, 0x53, 0x28, 0x28, 0x02,
    0xe8, 0xa2, 0x3e, 0x3d, 0xef, 0xf4, 0x47, 0xdd, 0x29, 0x5d, 0x94, 0xa4, 0x80, 0x5a, 0x06, 0xe5, 0xed, 0xc6, 0x40,
    0x10, 0x59, 0x28, 0x01, 0xad, 0x72, 0x81, 0x07, 0x39, 0x19, 0xa5, 0x10, 0xbe, 0xd3, 0xf6, 0x93, 0xe0, 0xdf, 0x0e,
    0x90, 0xff, 0x83, 0xd4, 0xc6, 0x13, 0xde, 0xfb, 0xe2, 0xb0, 0x07, 0xf8, 0x59, 0x45, 0x7e, 0xb9, 0x0d, 0x83, 0x7f,
    0x72, 0xa6, 0x17, 0x72, 0x8d, 0x47, 0xa3, 0x3f, 0xf2, 0xad, 0x00, 0x69, 0xc1, 0x36, 0xe3, 0x07, 0x09, 0x36, 0xbc,
    0x42, 0x5a, 0xff, 0xd9, 0x65, 0x8d, 0x92, 0xaf, 0xc9, 0x95, 0xce, 0x47, 0x32, 0xa5, 0xd3, 0xb2, 0xa0, 0x03, 0x69,
    0x9f, 0x42, 0xf5, 0x8e, 0xa1, 0x29, 0x18, 0xf9, 0x83};
#endif

const uint32_t s_rsa_exponent = RSA_EXPONENT;
const uint32_t a              = 2048 >> 4;

psa_status_t psa_to_ecc_group_id(psa_key_type_t key_type, psa_algorithm_t key_algo, mbedtls_ecp_group_id *ecp_grou_id)
{
    uint32_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
    uint32_t algo   = PSA_ALG_GET_HASH(key_algo);

    switch (family)
    {
        case PSA_ECC_FAMILY_SECP_K1:
        {
            switch (algo)
            {
                case PSA_ALG_SHA_224:
                {
                    *ecp_grou_id = MBEDTLS_ECP_DP_SECP224K1;
                    break;
                }
                case PSA_ALG_SHA_256:
                {
                    *ecp_grou_id = MBEDTLS_ECP_DP_SECP256K1;
                    break;
                }
                default:
                {
                    return PSA_ERROR_NOT_SUPPORTED;
                }
            }
        }
        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
        {
            switch (algo)
            {
                case PSA_ALG_SHA_256:
                {
                    *ecp_grou_id = MBEDTLS_ECP_DP_BP256R1;
                    break;
                }
                case PSA_ALG_SHA_384:
                {
                    *ecp_grou_id = MBEDTLS_ECP_DP_BP384R1;
                    break;
                }
                case PSA_ALG_SHA_512:
                {
                    *ecp_grou_id = MBEDTLS_ECP_DP_BP512R1;
                    break;
                }
                default:
                {
                    return PSA_ERROR_NOT_SUPPORTED;
                }
            }
        }
        default:
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    return PSA_SUCCESS;
}

// Functions
psa_status_t mcux_key_buf_to_raw_ecc(psa_key_type_t key_type,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     mcux_key_type_t req_key_type,
                                     mbedtls_ecp_group_id ecp_grou_id,
                                     struct ecc_keypair *ecc_key)
{
    psa_status_t status;
    mbedtls_ecdsa_context *ecc;
    int ret;
    size_t olen;
    size_t key_bits;

    (void)mbedtls_ecc_group_to_psa(ecp_grou_id, &key_bits);

    /* Parse input - We will use mbedtls_ecdsa_context to parse the context into */
    status = mbedtls_psa_ecp_load_representation(key_type, key_bits, key_buffer, key_buffer_size, &ecc);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    if (status == PSA_SUCCESS)
    {
        /* Alocate MPI structure for public key */
        status = mcux_alloc_raw_ecc(ecc_key, PSA_BITS_TO_BYTES(key_bits), req_key_type);
    }

    if ((req_key_type == MCUX_KEY_TYPE_KEYPAIR) || (req_key_type == MCUX_KEY_TYPE_PUBLIC))
    {
        /* Check whether the public part is loaded. If not, load it. */
        if (mbedtls_ecp_is_zero(&ecc->MBEDTLS_PRIVATE(Q)))
        {
            ret = mbedtls_ecp_mul(&ecc->MBEDTLS_PRIVATE(grp), &ecc->MBEDTLS_PRIVATE(Q), &ecc->MBEDTLS_PRIVATE(d),
                                  &ecc->MBEDTLS_PRIVATE(grp).G, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
            if (ret < 0)
            {
                status = PSA_ERROR_BAD_STATE;
            }
        }

        if (status == PSA_SUCCESS)
        {
            /* Read modulus data from MPI ctx structure */
            ret = mbedtls_ecp_point_write_binary(&ecc->MBEDTLS_PRIVATE(grp), &ecc->MBEDTLS_PRIVATE(Q),
                                                 MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                                 (unsigned char *)ecc_key->public_key, ecc_key->public_key_len);
            if (ret < 0)
            {
                status = PSA_ERROR_BAD_STATE;
            }
        }
    }

    if (status == PSA_SUCCESS)
    {
        if ((req_key_type == MCUX_KEY_TYPE_KEYPAIR) || (req_key_type == MCUX_KEY_TYPE_PRIVATE))
        {
            /* Read private exponent data from MPI ctx structure */
            ret = mbedtls_mpi_write_binary(&ecc->MBEDTLS_PRIVATE(d), (unsigned char *)ecc_key->private_key,
                                           ecc_key->private_key_len);
            if (ret < 0)
            {
                status = PSA_ERROR_BAD_STATE;
            }
        }
    }

    if (status != PSA_SUCCESS)
    {
        mcux_free_raw_ecc(ecc_key);
    }
    mbedtls_ecdsa_free(ecc);
    mbedtls_free(ecc);

    return status;
}

psa_status_t mcux_raw_ecc_to_key_buf(psa_key_type_t key_type,
                                     bool only_public,
                                     struct ecc_keypair *ecc_key,
                                     mbedtls_ecp_group_id ecp_grou_id,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     size_t *key_buffer_length)
{
    mbedtls_ecdsa_context ecc;
    psa_status_t status = PSA_SUCCESS;
    int ret;

    mbedtls_ecdsa_init(&ecc);

    mbedtls_ecp_group_init(&ecc.MBEDTLS_PRIVATE(grp));

    ret = mbedtls_ecp_group_load(&ecc.MBEDTLS_PRIVATE(grp), ecp_grou_id);

    if (ret == 0)
    {
        mbedtls_ecp_point_init(&ecc.MBEDTLS_PRIVATE(Q));

        ret = mbedtls_ecp_point_read_binary(&ecc.MBEDTLS_PRIVATE(grp), &ecc.MBEDTLS_PRIVATE(Q), ecc_key->public_key,
                                            ecc_key->public_key_len);
    }
    /* ADD ECC curve */

    if (ret == 0)
    {
        if (only_public)
        {
            key_type = PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY;
        }
        else
        {
            mbedtls_mpi_init(&ecc.MBEDTLS_PRIVATE(d));

            /* Read private exponent in MPI */
            ret = mbedtls_mpi_read_binary(&ecc.MBEDTLS_PRIVATE(d), (const unsigned char *)ecc_key->private_key,
                                          ecc_key->private_key_len);
        }
    }

    if (ret < 0)
    {
        status = PSA_ERROR_BAD_STATE;
    }

    if (status == PSA_SUCCESS)
    {
        status = mbedtls_psa_ecp_export_key(key_type, &ecc, (uint8_t *)key_buffer, key_buffer_size, key_buffer_length);
    }

    mbedtls_ecdsa_free(&ecc);

    return status;
}

psa_status_t mcux_alloc_raw_ecc(struct ecc_keypair *ecc_key, size_t key_bytes, mcux_key_type_t key_type)
{
    psa_status_t err = PSA_SUCCESS;

#if defined(USE_MALLOC)
    ecc_key->private_key = NULL;
    ecc_key->public_key  = NULL;
#endif
    ecc_key->private_key_len = 0;
    ecc_key->public_key_len  = 0;

    if ((key_type == MCUX_KEY_TYPE_PRIVATE) || (key_type == MCUX_KEY_TYPE_KEYPAIR))
    {
#if defined(USE_MALLOC)
        ecc_key->private_key = malloc(key_bytes);
        if (ecc_key->private_key == NULL)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#else
        if (key_bytes > sizeof(ecc_key->private_key))
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#endif
        ecc_key->private_key_len = key_bytes;
    }

    if ((key_type == MCUX_KEY_TYPE_PUBLIC) || (key_type == MCUX_KEY_TYPE_KEYPAIR))
    {
#if defined(USE_MALLOC)
        /* Alocate MPI structure for Private exponent */
        ecc_key->public_key = malloc(ECC_PUBLIC_KEY_SIZE(key_bytes));
        if (ecc_key->public_key == NULL)
        {
            if (ecc_key->private_key_len > 0)
            {
                free(ecc_key->private_key);
            }
            err = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#else
        if (ECC_PUBLIC_KEY_SIZE(key_bytes) > sizeof(ecc_key->public_key))
        {
            err = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#endif
        if (err == PSA_SUCCESS)
        {
            ecc_key->public_key_len = ECC_PUBLIC_KEY_SIZE(key_bytes);
        }
        else
        {
            ecc_key->private_key_len = 0;
        }
    }

    return err;
}

psa_status_t mcux_free_raw_ecc(struct ecc_keypair *ecc_key)
{
#if defined(USE_MALLOC)
    if (ecc_key->private_key_len && ecc_key->private_key)
    {
        free(ecc_key->private_key);
    }

    if (ecc_key->public_key_len && ecc_key->public_key)
    {
        free(ecc_key->public_key);
    }
#endif

    memset(ecc_key, 0, sizeof(*ecc_key));

    return PSA_SUCCESS;
}

psa_status_t mcux_key_buf_to_raw_rsa(psa_key_type_t key_type,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     uint32_t key_bytes,
                                     bool is_public,
                                     struct rsa_keypair *rsa_key,
                                     uint8_t rsa_exp[4])
{
    psa_status_t status;
    mbedtls_rsa_context *rsa = NULL;
    int ret;

    /* Parse input - We will use mbedtls_rsa_context to parse the context into*/
    status = mbedtls_psa_rsa_load_representation(key_type, key_buffer, key_buffer_size, &rsa);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    /* Alocate MPI structure for Public modulus */
    status = mcux_alloc_raw_rsa(rsa_key, key_bytes, (is_public) ? MCUX_KEY_TYPE_PUBLIC : MCUX_KEY_TYPE_KEYPAIR);
    if (status == PSA_SUCCESS)
    {
        if (is_public)
        {
            ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(E), rsa_exp, 4);
            if (ret < 0)
            {
                status = PSA_ERROR_BAD_STATE;
            }
        }
        else
        {
            /* Read private exponent data from MPI ctx structure */
            ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(D), (unsigned char *)rsa_key->priv_exp,
                                           rsa_key->priv_exp_len);
            if (ret < 0)
            {
                status = PSA_ERROR_BAD_STATE;
            }
        }
    }

    if (status == PSA_SUCCESS)
    {
        /* Read modulus data from MPI ctx structure */
        ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(N), (unsigned char *)rsa_key->modulus, key_bytes);

        if (ret < 0)
        {
            status = PSA_ERROR_BAD_STATE;
        }
    }

    if (status != PSA_SUCCESS)
    {
        mcux_free_raw_rsa(rsa_key);
    }

    mbedtls_rsa_free(rsa);
    mbedtls_free(rsa);

    return status;
}

psa_status_t mcux_raw_rsa_to_key_buf(psa_key_type_t key_type,
                                     bool only_public,
                                     struct rsa_keypair *rsa_key,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     size_t *key_buffer_length)
{
    mbedtls_rsa_context rsa;
    psa_status_t status = PSA_SUCCESS;
    int ret;

    mbedtls_rsa_init(&rsa);

    mbedtls_mpi_init(&rsa.MBEDTLS_PRIVATE(N));

    /* Read modulo in MPI */
    ret =
        mbedtls_mpi_read_binary(&rsa.MBEDTLS_PRIVATE(N), (const unsigned char *)rsa_key->modulus, rsa_key->modulus_len);
    if (ret == 0)
    {
        ret = mbedtls_mpi_lset(&rsa.MBEDTLS_PRIVATE(E), s_rsa_exponent);
    }

    if (ret == 0)
    {
        /* Set Ctx length */
        rsa.MBEDTLS_PRIVATE(len) = mbedtls_mpi_size(&rsa.MBEDTLS_PRIVATE(N));

        if (only_public)
        {
            key_type = PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY;
        }
        else
        {
            mbedtls_mpi_init(&rsa.MBEDTLS_PRIVATE(D));

            /* Read private exponent in MPI */
            ret = mbedtls_mpi_read_binary(&rsa.MBEDTLS_PRIVATE(D), (const unsigned char *)rsa_key->priv_exp,
                                          rsa_key->priv_exp_len);

            if (ret == 0)
            {
                /* Compute P and Q in CTX. */
                /* Needed as key buffer needs to be in PKCS1 format*/
                ret = mbedtls_rsa_complete(&rsa);
            }
        }
    }

    if (ret < 0)
    {
        status = PSA_ERROR_BAD_STATE;
    }

    if (status == PSA_SUCCESS)
    {
        status = mbedtls_psa_rsa_export_key(key_type, &rsa, (uint8_t *)key_buffer, key_buffer_size, key_buffer_length);
    }

    mbedtls_rsa_free(&rsa);

    return status;
}

psa_status_t mcux_alloc_raw_rsa(struct rsa_keypair *rsa_key, size_t key_bytes, mcux_key_type_t key_type)
{
    psa_status_t err = PSA_SUCCESS;

#if defined(USE_MALLOC)
    rsa_key->modulus  = NULL;
    rsa_key->priv_exp = NULL;
#endif
    rsa_key->modulus_len  = 0;
    rsa_key->priv_exp_len = 0;

    if ((key_type == MCUX_KEY_TYPE_PUBLIC) || (key_type == MCUX_KEY_TYPE_KEYPAIR))
    {
#if defined(USE_MALLOC)
        rsa_key->modulus = malloc(key_bytes);
        if (rsa_key->modulus == NULL)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#else
        if (key_bytes > sizeof(rsa_key->modulus))
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#endif
        rsa_key->modulus_len = key_bytes;
    }

    if ((key_type == MCUX_KEY_TYPE_PRIVATE) || (key_type == MCUX_KEY_TYPE_KEYPAIR))
    {
#if defined(USE_MALLOC)
        /* Alocate MPI structure for Private exponent */
        rsa_key->priv_exp = malloc(key_bytes);
        if (rsa_key->priv_exp == NULL)
        {
            if (rsa_key->modulus > 0)
            {
                free(rsa_key->modulus);
            }
            err = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#else
        if (key_bytes > sizeof(rsa_key->priv_exp))
        {
            err = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#endif
        if (err == PSA_SUCCESS)
        {
            rsa_key->priv_exp_len = key_bytes;
        }
        else
        {
            rsa_key->modulus_len = 0;
        }
    }
    return err;
}

psa_status_t mcux_free_raw_rsa(struct rsa_keypair *rsa_key)
{
#if defined(USE_MALLOC)
    if (rsa_key->modulus_len && rsa_key->modulus)
    {
        free(rsa_key->modulus);
    }

    if (rsa_key->priv_exp_len && rsa_key->priv_exp)
    {
        free(rsa_key->priv_exp);
    }
#endif

    memset(rsa_key, 0, sizeof(*rsa_key));

    return PSA_SUCCESS;
}

psa_status_t mcux_rsa_gemerate_primes(size_t bit_size, struct rsa_primes *primes)
{
    int status = 0;
#ifdef MCUX_RSA_PRIMES_CUSTOM
    const uint8_t *primeP;
    const uint8_t *primeQ;

#if defined(USE_MALLOC)
    primes->p = NULL;
    primes->q = NULL;
#endif

    switch (bit_size)
    {
        case 2048u:
        {
            primeP = s_primeP2048;
            primeQ = s_primeQ2048;
            break;
        }
        case 3072u:
        {
            primeP = s_primeP3072;
            primeQ = s_primeQ3072;
            break;
        }
        case 4096u:
        {
            primeP = s_primeP4096;
            primeQ = s_primeQ4096;
            break;
        }
        default:
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    primes->len = (bit_size >> 1) / 8;
#if defined(USE_MALLOC)
    primes->p = malloc(primes->len);
    primes->q = malloc(primes->len);
    if ((primes->p == NULL) || (primes->q == NULL))
    {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#else
    if ((sizeof(primes->p) < prime->len) || (sizeof(primes->q) < prime->len))
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#endif

    if (status == 0)
    {
        memcpy(primes->p, primeP, primes->len);
        memcpy(primes->q, primeQ, primes->len);
    }
#else
    mbedtls_mpi P, Q, H;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "rsa_primes";

#if defined(USE_MALLOC)
    primes->p = NULL;
    primes->q = NULL;
#endif

    primes->len = (bit_size >> 1) / 8;

    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    status =
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    // Generate two prime numbers for RSA
    do
    {
        if (status == 0)
        {
            status = mbedtls_mpi_gen_prime(&P, bit_size >> 1, 1, mbedtls_ctr_drbg_random, &ctr_drbg);
        }

        if (status == 0)
        {
            status = mbedtls_mpi_gen_prime(&Q, bit_size >> 1, 1, mbedtls_ctr_drbg_random, &ctr_drbg);
        }

        if (status == 0)
        {
            status = mbedtls_mpi_sub_mpi(&H, &P, &Q);
        }
        if (status == 0)
        {
            /* make sure the difference between p and q is not too small (FIPS 186-4 §B.3.3 step 5.4) */
            if (mbedtls_mpi_bitlen(&H) <= ((bit_size >= 200) ? ((bit_size >> 1) - 99) : 0))
            {
                continue;
            }

            /* not required by any standards, but some users rely on the fact that P > Q */
            if (H.MBEDTLS_PRIVATE(s) < 0)
            {
                mbedtls_mpi_swap(&P, &Q);
            }
            break;
        }
    } while (status == 0);

    if (status == 0)
    {
#if defined(USE_MALLOC)
        primes->p = malloc(primes->len);
        primes->q = malloc(primes->len);
        if ((primes->p == NULL) || (primes->q == NULL))
        {
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#else
        if ((sizeof(primes->p) < prime->len) || (sizeof(primes->q) < prime->len))
        {
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
#endif
    }

    if (status == 0)
    {
        status = mbedtls_mpi_write_binary(&P, (unsigned char *)primes->p, primes->len);
    }
    if (status == 0)
    {
        status = mbedtls_mpi_write_binary(&Q, (unsigned char *)primes->q, primes->len);
    }

    // Cleanup
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#endif

    if (status == 0)
    {
        return PSA_SUCCESS;
    }
    else
    {
        mcux_rsa_free_primes(primes);
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t mcux_rsa_free_primes(struct rsa_primes *primes)
{
#if defined(USE_MALLOC)
    if (primes->p != NULL)
    {
        free(primes->p);
    }
    if (primes->q != NULL)
    {
        free(primes->q);
    }
    primes->len = 0;
#else
    memset(primes, 0, sizeof(*primes));
#endif

    return PSA_SUCCESS;
}

/** @} */ // end of psa_key_generation
