/*
 * Copyright 2024-2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_s2xx_hash.c
 *
 * This file contains the implementation of the entry points associated to the
 * hash capability (single-part and multipart) as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_s2xx_init.h"
#include "mcux_psa_s2xx_hash.h"

/* To be able to include the PSA style configuration */
#include "mbedtls/build_info.h"

#define SHA224_DIGEST_SIZE_IN_BYTES (224u / 8u)
#define SHA256_DIGEST_SIZE_IN_BYTES (256u / 8u)
#define SHA384_DIGEST_SIZE_IN_BYTES (384u / 8u)
#define SHA512_DIGEST_SIZE_IN_BYTES (512u / 8u)

#define HASH_OPS_METADATA_MAX 16

typedef struct hash_op_metadata {
    ele_s2xx_hash_operation_t *op;
    psa_algorithm_t alg;
    int initialized;
} hash_op_metadata_t;

/* Hash operation monitoring for low-power */
static hash_op_metadata_t hash_op[HASH_OPS_METADATA_MAX];
static uint8_t hash_op_count = 0;

static psa_status_t register_hash_operation(ele_s2xx_hash_operation_t *operation, psa_algorithm_t alg);
static psa_status_t unregister_hash_operation(ele_s2xx_hash_operation_t *operation);
static hash_op_metadata_t *get_hash_op_metadata(ele_s2xx_hash_operation_t *operation);

static psa_status_t translate_psa_hash_to_ele_hash(psa_algorithm_t alg, sss_algorithm_t *mode)
{
    psa_status_t status = PSA_SUCCESS;
    switch (alg)
    {
#if defined(PSA_WANT_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            *mode = kAlgorithm_SSS_SHA224;
            break;
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            *mode = kAlgorithm_SSS_SHA256;
            break;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            *mode = kAlgorithm_SSS_SHA384;
            break;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            *mode = kAlgorithm_SSS_SHA512;
            break;
#endif /* PSA_WANT_ALG_SHA_512 */
#if defined(ELE_HAVE_SHA3)
#if defined(PSA_WANT_ALG_SHA3_224)
        case PSA_ALG_SHA3_224:
            *mode = kAlgorithm_SSS_SHA3_224;
            break;
#endif /* PSA_WANT_ALG_SHA3_224 */
#if defined(PSA_WANT_ALG_SHA3_256)
        case PSA_ALG_SHA3_256:
            *mode = kAlgorithm_SSS_SHA3_256;
            break;
#endif /* PSA_WANT_ALG_SHA3_256 */
#if defined(PSA_WANT_ALG_SHA3_384)
        case PSA_ALG_SHA3_384:
            *mode = kAlgorithm_SSS_SHA3_384;
            break;
#endif /* PSA_WANT_ALG_SHA3_384 */
#if defined(PSA_WANT_ALG_SHA3_512)
        case PSA_ALG_SHA3_512:
            *mode = kAlgorithm_SSS_SHA3_512;
            break;
#endif /* PSA_WANT_ALG_SHA3_512 */
#endif /* ELE_HAVE_SHA3 */
#if defined(PSA_WANT_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            *mode = kAlgorithm_SSS_SHA1;
            break;
#endif /* PSA_WANT_ALG_SHA_1 */
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }
    return status;
}

#if defined(ELE_FEATURE_DIGEST_CLONE) && (ELE_FEATURE_DIGEST_CLONE == 1)
/**
 * @brief Inverse to translate_psa_hash_to_ele_hash()
 */
static psa_status_t translate_ele_hash_to_psa_hash(sss_algorithm_t mode, psa_algorithm_t *alg)
{
    psa_status_t status = PSA_SUCCESS;
    switch (mode)
    {
#if defined(PSA_WANT_ALG_SHA_224)
        case kAlgorithm_SSS_SHA224:
            *alg = PSA_ALG_SHA_224;
            break;
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_256)
        case kAlgorithm_SSS_SHA256:
            *alg = PSA_ALG_SHA_256;
            break;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
        case kAlgorithm_SSS_SHA384:
            *alg = PSA_ALG_SHA_384;
            break;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
        case kAlgorithm_SSS_SHA512:
            *alg = PSA_ALG_SHA_512;
            break;
#endif /* PSA_WANT_ALG_SHA_512 */
#if defined(ELE_HAVE_SHA3)
#if defined(PSA_WANT_ALG_SHA3_224)
        case kAlgorithm_SSS_SHA3_224:
            *alg = PSA_ALG_SHA3_224;
            break;
#endif /* PSA_WANT_ALG_SHA3_224 */
#if defined(PSA_WANT_ALG_SHA3_256)
        case kAlgorithm_SSS_SHA3_256:
            *alg = PSA_ALG_SHA3_256;
            break;
#endif /* PSA_WANT_ALG_SHA3_256 */
#if defined(PSA_WANT_ALG_SHA3_384)
        case kAlgorithm_SSS_SHA3_384:
            *alg = PSA_ALG_SHA3_384;
            break;
#endif /* PSA_WANT_ALG_SHA3_384 */
#if defined(PSA_WANT_ALG_SHA3_512)
        case kAlgorithm_SSS_SHA3_512:
            *alg = PSA_ALG_SHA3_512;
            break;
#endif /* PSA_WANT_ALG_SHA3_512 */
#endif /* ELE_HAVE_SHA3 */
#if defined(PSA_WANT_ALG_SHA_1)
        case kAlgorithm_SSS_SHA1:
            *alg = PSA_ALG_SHA_1;
            break;
#endif /* PSA_WANT_ALG_SHA_1 */
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }
    return status;
}
#endif /* ELE_FEATURE_DIGEST_CLONE */

/** \defgroup psa_hash PSA driver entry points for hashing
 *
 *  Entry points for hashing operations as described by the PSA Cryptoprocessor
 *  Driver interface specification
 *
 *  @{
 */
psa_status_t ele_s2xx_transparent_hash_setup(ele_s2xx_hash_operation_t *operation, psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (NULL == operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    (void)memset(operation, 0, sizeof(ele_s2xx_hash_operation_t));

    if ((status = translate_psa_hash_to_ele_hash(alg, &operation->ctx.algorithm)) != PSA_SUCCESS)
    {
        return status;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (sss_sscp_digest_context_init(&operation->ctx, &g_ele_ctx.sssSession, operation->ctx.algorithm,
                                     kMode_SSS_Digest) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (sss_sscp_digest_init(&operation->ctx) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

exit:
    if (status == PSA_SUCCESS) {
        hash_op_metadata_t *metadata;

        /* Register hash operation for monitoring and mark it as "initialized" */
        register_hash_operation(operation, alg);
        metadata = get_hash_op_metadata(operation);
        if (metadata != NULL)
        {
            metadata->initialized = 1;
        }
    }

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_s2xx_transparent_hash_clone(const ele_s2xx_hash_operation_t *source_operation,
                                             ele_s2xx_hash_operation_t *target_operation)
{
#if defined(ELE_FEATURE_DIGEST_CLONE) && (ELE_FEATURE_DIGEST_CLONE == 1)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t alg = PSA_ALG_NONE;

    if (source_operation == NULL || target_operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize target to same algorithm as source */
    if ((status = translate_ele_hash_to_psa_hash(source_operation->ctx.algorithm, &alg)) != PSA_SUCCESS)
    {
        return status;
    }

    if ((status = ele_s2xx_transparent_hash_setup(target_operation, alg)) != PSA_SUCCESS)
    {
        return status;
    }

    /* Clone */
    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (sss_sscp_digest_clone((sss_sscp_digest_t *)&source_operation->ctx, &target_operation->ctx) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

exit:
    if (status == PSA_SUCCESS) {
        hash_op_metadata_t *metadata;

        /* Register hash operation for monitoring and mark it as "initialized" */
        register_hash_operation(target_operation, alg);
        metadata = get_hash_op_metadata(target_operation);
        if (metadata != NULL)
        {
            metadata->initialized = 1;
        }
    }

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
#else /* ELE_FEATURE_DIGEST_CLONE */
    (void)source_operation;
    (void)target_operation;
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* ELE_FEATURE_DIGEST_CLONE */
}

psa_status_t ele_s2xx_transparent_hash_update(ele_s2xx_hash_operation_t *operation,
                                              const uint8_t *input,
                                              size_t input_length)
{
    psa_status_t status = PSA_SUCCESS;
    hash_op_metadata_t *metadata;

    if (NULL == operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0u == input_length)
    {
        /* This is a valid situation, no need to call ele_hash_update.
         * ele_hash_finish will produce the result.
         */
        return PSA_SUCCESS;
    }

    /* if len not zero, but pointer is NULL */
    if (NULL == input)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* If the hash operation has lost context, re-initialize it */
    metadata = get_hash_op_metadata(operation);
    if (metadata->initialized != 1)
    {
        ele_s2xx_transparent_hash_setup(operation, metadata->alg);
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (sss_sscp_digest_update(&operation->ctx, (uint8_t *)(uintptr_t)input, input_length) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_s2xx_transparent_hash_finish(ele_s2xx_hash_operation_t *operation,
                                              uint8_t *hash,
                                              size_t hash_size,
                                              size_t *hash_length)
{
    psa_status_t status = PSA_SUCCESS;

    if (operation == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check if hash_size is sufficient or not */
    if (NULL == hash || hash_size < operation->ctx.digestFullLen)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (sss_sscp_digest_finish(&operation->ctx, hash, &hash_size) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    *hash_length = operation->ctx.digestFullLen;

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

psa_status_t ele_s2xx_transparent_hash_abort(ele_s2xx_hash_operation_t *operation)
{
    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    (void)sss_sscp_digest_context_free(&operation->ctx);

    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Zeroize the context */
    (void)memset(operation, 0, sizeof(ele_s2xx_hash_operation_t));

    /* Remove the hash operation from the monitoring table */
    unregister_hash_operation(operation);

    return PSA_SUCCESS;
}

psa_status_t ele_s2xx_transparent_hash_compute(psa_algorithm_t alg,
                                               const uint8_t *input,
                                               size_t input_length,
                                               uint8_t *hash,
                                               size_t hash_size,
                                               size_t *hash_length)
{
    psa_status_t status       = PSA_ERROR_CORRUPTION_DETECTED;
    size_t actual_hash_length = PSA_HASH_LENGTH(alg);
    sss_sscp_digest_t ctx;
    sss_algorithm_t mode = 0;

    if ((status = translate_psa_hash_to_ele_hash(alg, &mode)) != PSA_SUCCESS)
    {
        return status;
    }

    if (NULL == hash || 0u == hash_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly.
     */
    (void)memset(hash, (int)'!', hash_size);

    if (hash_size < actual_hash_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (sss_sscp_digest_context_init(&ctx, &g_ele_ctx.sssSession, mode, kMode_SSS_Digest) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    *hash_length = ctx.digestFullLen;

    if (sss_sscp_digest_one_go(&ctx, input, input_length, hash, hash_length) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (sss_sscp_digest_context_free(&ctx) != kStatus_SSS_Success)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex) != 0)
    {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

/* Register a hash operation for monitoring */
static psa_status_t register_hash_operation(ele_s2xx_hash_operation_t *operation, psa_algorithm_t alg)
{
    hash_op_metadata_t *metadata;

    metadata = get_hash_op_metadata(operation);
    if (metadata != NULL)
    {
        /* Hash op is already monitored */
        return PSA_SUCCESS;
    }

    if (hash_op_count >= HASH_OPS_METADATA_MAX)
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    memset(&hash_op[hash_op_count], 0, sizeof(hash_op_metadata_t));
    hash_op[hash_op_count].op = operation;
    hash_op[hash_op_count].alg = alg;

    hash_op_count++;

    return PSA_SUCCESS;
}

/* Remove a hash operation from the monitoring table */
static psa_status_t unregister_hash_operation(ele_s2xx_hash_operation_t *operation)
{
    int i = 0;

    while ((i < hash_op_count) && (hash_op[i].op != operation))
    {
        i++;
    }

    if (i >= hash_op_count)
    {
        /* Couldn't find the hash op */
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Shift back all remaining hash ops, if any */
    while (i < hash_op_count - 1)
    {
        memcpy(&hash_op[i], &hash_op[i + 1], sizeof(hash_op_metadata_t));
        i++;
    }
    hash_op_count--;

    return PSA_SUCCESS;
}

/* Get the monitoring metadata for a specific hash op */
static hash_op_metadata_t *get_hash_op_metadata(ele_s2xx_hash_operation_t *operation)
{
    int i = 0;

    while ((i < hash_op_count) && (hash_op[i].op != operation))
    {
        i++;
    }

    if (i >= hash_op_count)
    {
        /* Couldn't find the hash op */
        return NULL;
    }

    return &hash_op[i];
}

/* Mark all monitored hash ops for reinitialization */
psa_status_t ele_s2xx_reinit_all_hash_ops(void)
{
    int i = 0;

    while (i < hash_op_count)
    {
        hash_op[i++].initialized = 0;
    }

    return PSA_SUCCESS;
}

/** @} */ // end of psa_hash
