/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SGI_CRYPTO_PRIMITIVES_H
#define SGI_CRYPTO_PRIMITIVES_H

/** \file sgi_crypto_primtives.h
 *
 * This file contains the declaration of the context structures related
 * to the SGI HW
 *
 */

#include <mcuxClHash.h> // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>

#include <mcuxClMacModes.h>

#include <mcuxClCipher.h>
#include <mcuxClCipherModes.h>
#include <mcuxClKey.h>

#include <mcuxClAeadModes.h>

/* Determine the maximum hash context size needed.
 * SHA3-224 has the largest context (376 bytes on platforms with SHA3 support),
 * which is bigger than SHA2-512 (224 bytes). Use SHA3-224 size when SHA3 is
 * available, otherwise fall back to SHA2-512. */
#if defined(MCUXCL_FEATURE_HASH_C_SHA3)
#define MCUX_SGI_HASH_CTX_SIZE_IN_WORDS  MCUXCLHASH_CONTEXT_SIZE_SHA3_224_IN_WORDS
#else
#define MCUX_SGI_HASH_CTX_SIZE_IN_WORDS  MCUXCLHASH_CONTEXT_SIZE_SHA2_512_IN_WORDS
#endif /* MCUXCL_FEATURE_HASH_C_SHA3 */

typedef struct {
    uint32_t ctx[MCUX_SGI_HASH_CTX_SIZE_IN_WORDS];
} mcux_sgi_hash_operation_t;


typedef struct {
    uint32_t ctx[MCUXCLMAC_CONTEXT_SIZE_IN_WORDS];
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
} sgi_mac_operation_t;

typedef struct {
    uint32_t ctx[MCUXCLAEAD_CONTEXT_SIZE];
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];

    psa_algorithm_t alg;
    psa_key_type_t key_type;
    uint8_t is_encrypt;
    uint32_t tag_length;

    uint32_t body_started;
    uint32_t ad_remaining;
    uint32_t body_remaining;
    uint32_t nonce_set;
} sgi_aead_operation_t;

typedef struct {
    uint32_t ctx[MCUXCLCIPHER_AES_CONTEXT_SIZE_IN_WORDS];
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    psa_algorithm_t alg;
    psa_key_type_t key_type;
    psa_encrypt_or_decrypt_t cipher_direction;
} sgi_cipher_operation_t;
#endif /* SGI_CRYPTO_PRIMITIVES_H */
