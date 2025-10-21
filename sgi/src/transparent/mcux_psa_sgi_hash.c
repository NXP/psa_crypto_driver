/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_sgi_hash.c
 *
 * This file contains the implementation of the entry points associated to the
 * hash capability (single-part and multipart) as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_sgi_init.h"
#include "mcux_psa_sgi_hash.h"

/* To be able to include the PSA style configuration */
#include "mbedtls/build_info.h"

#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClSession.h>
#include <mcuxClMemory_Copy.h>
#include <mcuxClMemory_Clear.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClHash_Internal.h>

typedef struct {
    mcuxClHash_ContextDescriptor_t ctx;
} psa_sgi_hash_ctx_t;

static inline psa_sgi_hash_ctx_t *psa_sgi_get_ctx(mcux_sgi_hash_operation_t *operation)
{
    return (psa_sgi_hash_ctx_t *) operation->ctx;
}

const mcuxClHash_AlgorithmDescriptor_t *psa_hash_alg_to_sgi_hash_alg(psa_algorithm_t alg)
{
    switch (alg) {
#if defined(PSA_WANT_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            return mcuxClHash_Algorithm_Sha224;
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            return mcuxClHash_Algorithm_Sha256;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            return mcuxClHash_Algorithm_Sha384;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            return mcuxClHash_Algorithm_Sha512;
#endif /* PSA_WANT_ALG_SHA_512 */
        default:
            return NULL;
    }
}

/** \defgroup psa_hash PSA driver entry points for hashing
 *
 *  Entry points for hashing operations as described by the PSA Cryptoprocessor
 *  Driver interface specification
 *
 *  @{
 */
psa_status_t sgi_hash_setup(mcux_sgi_hash_operation_t *operation, psa_algorithm_t alg)
{
    if (NULL == operation) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memset(operation, 0, sizeof(mcux_sgi_hash_operation_t));

    /* Select algorithm descriptor */
    const mcuxClHash_AlgorithmDescriptor_t *hashAlgo = psa_hash_alg_to_sgi_hash_alg(alg);

    if (NULL == hashAlgo) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClHash_init(
                                         /* mcuxCLSession_Handle_t session: */ session,
                                         /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t)
                                         &operation->ctx,
                                         /* mcuxClHash_Algo_t  algo:        */ hashAlgo));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != token) ||
        (MCUXCLHASH_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_hash_clone(const mcux_sgi_hash_operation_t *source_operation,
                            mcux_sgi_hash_operation_t *target_operation)
{

    if (source_operation == NULL || target_operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Copy content from mcuxClHash_Context_t */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("copy only reads from source")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(tokenCopy1, mcuxClMemory_copy(
                                              (uint8_t *) target_operation->ctx,
                                              (uint8_t *) source_operation->ctx,
                                              sizeof(mcuxClHash_ContextDescriptor_t),
                                              sizeof(mcuxClHash_ContextDescriptor_t)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenCopy1) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    /* Compute new position and length of buffers*/

    psa_sgi_hash_ctx_t *p_target_data = (psa_sgi_hash_ctx_t *) target_operation->ctx;
    psa_sgi_hash_ctx_t *p_source_data = (psa_sgi_hash_ctx_t *) source_operation->ctx;
    uint32_t *pStateTarget = mcuxClHash_getStatePtr(&p_target_data->ctx);
    uint32_t *pStateSource = mcuxClHash_getStatePtr(&p_source_data->ctx);

    size_t bufferSizes = p_source_data->ctx.algo->stateSize + p_source_data->ctx.algo->blockSize;

    /* Copy state and unprocessed buffer to target hash operation handle. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(tokenCopy2, mcuxClMemory_copy(
                                              (uint8_t *) pStateTarget,
                                              (uint8_t *) pStateSource,
                                              bufferSizes,
                                              bufferSizes));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenCopy2) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    /* Remaining Bytes in source and target behind pUnprocessed are not accessed by hash algorithms, so we do not copy them. */

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_hash_update(mcux_sgi_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length)
{
    if (NULL == operation) {
        // ELE_OSAL_LOG_ERR("operation is NULL");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0u == input_length) {
        /* This is a valid situation, no need to call ele_hash_update.
         * ele_hash_finish will produce the result.
         */
        return PSA_SUCCESS;
    }

    /* if len not zero, but pointer is NULL */
    if (NULL == input) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /* Perform the hashing operation */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token, mcuxClHash_process(session,
                                          (mcuxClHash_Context_t) &operation->ctx,
                                          input,
                                          input_length));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token) ||
        (MCUXCLHASH_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_hash_finish(mcux_sgi_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Set hash_length correctly and check consistency with hash_size */
    psa_sgi_hash_ctx_t *p_hash_data = psa_sgi_get_ctx(operation);

    /* Check if hash_size is sufficient or not */
    if (!hash || hash_size < p_hash_data->ctx.algo->hashSize) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }


    /* Set hash_length and check consistency with Algo->hashSize */
    *hash_length = hash_size;

    /* Update the actual hashsize from algorithum*/
    *hash_length = p_hash_data->ctx.algo->hashSize;

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /* Perform the hashing operation */
    uint32_t hashOutputSize = 0;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClHash_finish(session,
                                                       &p_hash_data->ctx,
                                                       hash,
                                                       &hashOutputSize));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != token) ||
        (MCUXCLHASH_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t sgi_hash_abort(mcux_sgi_hash_operation_t *operation)
{
    /* Clear hash clns data (context) */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(
        token, mcuxClMemory_clear((uint8_t *) operation->ctx,
                                  MCUXCLHASH_CONTEXT_SIZE_SHA2_512_IN_WORDS,
                                  MCUXCLHASH_CONTEXT_SIZE_SHA2_512_IN_WORDS));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) != token) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    return PSA_SUCCESS;
}

psa_status_t sgi_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length)
{
    size_t actual_hash_length = PSA_HASH_LENGTH(alg);

    /* Select algorithm descriptor */
    const mcuxClHash_AlgorithmDescriptor_t *hashAlgo = psa_hash_alg_to_sgi_hash_alg(alg);

    if (NULL == hashAlgo) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!hash || !hash_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */

    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if (hash_size != 0u) {
        memset(hash, '!', hash_size);
    }

    if (hash_size < actual_hash_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    /* Create session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /* Perform the hashing operation */
    uint32_t hashOutputSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClHash_compute(session,
                                                        hashAlgo,
                                                        input,
                                                        input_length,
                                                        hash,
                                                        &hashOutputSize));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != token) ||
        (MCUXCLHASH_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Update the hash length */
    if (hash_length != NULL) {
        *hash_length = hashAlgo->hashSize;
    }

    /* Destroy the session */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}
/** @} */ // end of psa_hash
