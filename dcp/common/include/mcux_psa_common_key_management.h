/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_COMMON_KEY_MANAGEMENT_H
#define MCUX_PSA_COMMON_KEY_MANAGEMENT_H

/** \file mcux_psa_common_key_management.h
 *
 * This file contains the declaration of the entry points associated to the
 * key generation (i.e. random generation and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "psa/crypto.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RSA_KEYSIZE (4096 / 8)
#define MAX_ECC_KEYSIZE (576 / 8)
#define MAX_AES_KEYSIZE (256 / 8)

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
#define MAX_KEYSIZE MAX_RSA_KEYSIZE
#elif defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
#define MAX_KEYSIZE MAX_ECC_KEYSIZE
#endif

#define USE_MALLOC

#ifndef RSA_EXPONENT
#define RSA_EXPONENT 65537u
#endif /* RSA_EXPONENT */

#define ECC_PUBLIC_KEY_SIZE(bytes) (bytes * 2 + 1)

#if defined(USE_MALLOC)
struct rsa_primes
{
    size_t len;
    uint8_t *p;
    uint8_t *q;
};

struct rsa_keypair
{
    size_t modulus_len;
    size_t priv_exp_len;
    uint8_t *modulus;
    uint8_t *priv_exp;
};

struct ecc_keypair
{
    size_t private_key_len;
    size_t public_key_len;
    uint8_t *private_key;
    uint8_t *public_key;
};
#else
struct rsa_primes
{
    size_t len;
    uint8_t p[MAX_RSA_KEYSIZE / 2];
    uint8_t q[MAX_RSA_KEYSIZE / 2];
};

struct rsa_keypair
{
    size_t modulus_len;
    size_t priv_exp_len;
    uint8_t modulus[MAX_RSA_KEYSIZE];
    uint8_t priv_exp[MAX_RSA_KEYSIZE];
};

struct ecc_keypair
{
    size_t private_key_len;
    size_t public_key_len;
    uint8_t private_key[MAX_ECC_KEYSIZE];
    uint8_t public_key[ECC_PUBLIC_KEY_SIZE(MAX_ECC_KEYSIZE)];
};
#endif

typedef enum _mcux_key_type
{
    MCUX_KEY_TYPE_PUBLIC  = 1,
    MCUX_KEY_TYPE_PRIVATE = 2,
    MCUX_KEY_TYPE_KEYPAIR = 3,
} mcux_key_type_t;

/* In mbedTLS 3.6 they have removed the domain parameter concept so hardcode exponent to 65537 */
extern const uint32_t s_rsa_exponent;

psa_status_t psa_to_ecc_group_id(psa_key_type_t key_type, psa_algorithm_t key_algo, mbedtls_ecp_group_id *ecp_grou_id);

/* Convert the content of key buffer to struct ecc_priv -> RAW binary format */
psa_status_t mcux_key_buf_to_raw_ecc(psa_key_type_t key_type,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     mcux_key_type_t is_public,
                                     mbedtls_ecp_group_id ecp_grou_id,
                                     struct ecc_keypair *ecc_key);

/* Convert struct ECC raw binary format to key buffer content
 *  For now to keep things simple, we are assuming key buffer is in ASN1 format.
 */
psa_status_t mcux_raw_ecc_to_key_buf(psa_key_type_t key_type,
                                     bool only_public,
                                     struct ecc_keypair *ecc_key,
                                     mbedtls_ecp_group_id ecp_grou_id,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     size_t *key_buffer_length);

psa_status_t mcux_alloc_raw_ecc(struct ecc_keypair *ecc_key, size_t key_bytes, mcux_key_type_t key_type);
psa_status_t mcux_free_raw_ecc(struct ecc_keypair *ecc_key);

/* Convert the content of key buffer to struct rsa_priv -> RAW binary format */
psa_status_t mcux_key_buf_to_raw_rsa(psa_key_type_t key_type,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     uint32_t key_bytes,
                                     bool is_public,
                                     struct rsa_keypair *rsa_key,
                                     uint8_t rsa_exp[4]);

/* Convert struct RSA raw binary format to key buffer content
 *  For now to keep things simple, we are assuming key buffer is in ASN1 format.
 */
psa_status_t mcux_raw_rsa_to_key_buf(psa_key_type_t key_type,
                                     bool only_public,
                                     struct rsa_keypair *rsa_key,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     size_t *key_buffer_length);

psa_status_t mcux_alloc_raw_rsa(struct rsa_keypair *rsa_key, size_t key_bytes, mcux_key_type_t key_type);
psa_status_t mcux_free_raw_rsa(struct rsa_keypair *rsa_key);

psa_status_t mcux_rsa_gemerate_primes(size_t bit_size, struct rsa_primes *primes);
psa_status_t mcux_rsa_free_primes(struct rsa_primes *primes);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_COMMON_KEY_MANAGEMENT_H */
