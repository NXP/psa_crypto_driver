/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_SGI_SESSION_HELPER_H
#define MCUX_PSA_SGI_SESSION_HELPER_H

/** \file mcux_psa_sgi_session_helper.h
 *
 * Session/RNG helper macros for the SGI PSA crypto driver.
 *
 * The macros below therefore never return by themselves. On failure they set
 * the caller-provided psa_status_t variable and jump to a caller-provided
 * label (the function's existing "cleanup" label), so the mutex is released
 * and the session is destroyed on every path.
 */

#include "psa/crypto.h"

#include <mcuxClSession.h>
#include <mcuxClResource.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <platform_specific_headers.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @brief Bind the shared crypto-driver-wide single resource context to a
 *        session.
 *
 * The resource context is a single static instance shared by the SGI and PKC
 * PSA drivers (defined in the SGI common init translation unit). Because every
 * driver entry point creates and destroys its own mcuxClSession (and session
 * destroy releases the resource context's HW arbitration state), the single
 * static context is re-initialized on every call before being bound to the
 * supplied session. All calls are expected to be serialized by the owning HW
 * mutex, so no additional locking is done here.
 *
 * @param[in] session  Handle for the current CL session.
 *
 * @retval PSA_SUCCESS on success.
 * @retval PSA_ERROR_HARDWARE_FAILURE if the resource context could not be
 *         initialized or bound to the session.
 */
#ifndef MCUXCL_PSA_SESSION_SET_RESOURCE_DECLARED
#define MCUXCL_PSA_SESSION_SET_RESOURCE_DECLARED
psa_status_t mcux_psa_session_set_resource(mcuxClSession_Handle_t session);
#endif /* MCUXCL_PSA_SESSION_SET_RESOURCE_DECLARED */

/* The session/RNG helper macros are shared between the SGI
 * and PKC session helpers, and both call the same shared
 * mcux_psa_session_set_resource() */

/* Always allocate at least one CPU word to avoid zero-length arrays. */
#ifndef MCUXCL_PSA_ALLOCATE_CPUWA
#define MCUXCL_PSA_ALLOCATE_CPUWA(cpuWaLength)                                                          \
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CONTROLLING_EXPRESSION_IS_INVARIANT("Constant values are allowed as an argument to macro function") \
        ((((sizeof(uint32_t)) <= (cpuWaLength)) ? (cpuWaLength) : sizeof(uint32_t)) / (sizeof(uint32_t))) \
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CONTROLLING_EXPRESSION_IS_INVARIANT()


#define MCUXCL_PSA_MAX_WA(a, b)                                                                         \
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CONTROLLING_EXPRESSION_IS_INVARIANT("Constant values are allowed as an argument to macro function") \
        (((a) > (b)) ? (a) : (b))                                                                       \
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CONTROLLING_EXPRESSION_IS_INVARIANT()

/*!
 * @brief Allocate the CPU work area, initialize the session and bind the
 *        driver-wide single resource context.
 *
 * On failure this macro does NOT return. It assigns a psa_status_t to
 * (status_out) and jumps to (fail_label) so the caller's cleanup path (mutex
 * unlock and session destroy) always runs.
 *
 * @param pSession     mcuxClSession_Handle_t for the current CL session.
 * @param cpuWaLength  Size in bytes of the CPU work area (multiple of CPU word).
 * @param pkcWaLength  Size in bytes of the PKC work area.
 * @param status_out   value of type psa_status_t updated on failure.
 * @param fail_label   label to jump to on failure (typically "cleanup").
 */
#define MCUXCL_ALLOCATE_AND_INITIALIZE_SESSION(pSession, cpuWaLength, pkcWaLength, status_out, fail_label)  \
    uint32_t cpuWaBuffer[MCUXCL_PSA_ALLOCATE_CPUWA(cpuWaLength)];                                           \
    do {                                                                                                   \
        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(si_status, si_token, mcuxClSession_init(                           \
            /* mcuxClSession_Handle_t session:  */ (pSession),                                             \
            /* uint32_t * const cpuWaBuffer:    */ cpuWaBuffer,                                            \
            /* uint32_t cpuWaSize:              */ (cpuWaLength),                                          \
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER()                                     \
            /* uint32_t * const pkcWaBuffer:    */ (uint32_t *) PKC_RAM_ADDR,                              \
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()                                      \
            /* uint32_t pkcWaSize:              */ (pkcWaLength)                                           \
            ));                                                                                            \
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != si_token)) {                              \
            (status_out) = PSA_ERROR_CORRUPTION_DETECTED;                                                  \
            goto fail_label;                                                                              \
        }                                                                                                  \
        if (MCUXCLSESSION_STATUS_OK != si_status) {                                                        \
            (status_out) = PSA_ERROR_HARDWARE_FAILURE;                                                     \
            goto fail_label;                                                                              \
        }                                                                                                  \
        MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                  \
        psa_status_t res_status = mcux_psa_session_set_resource(pSession);                                  \
        if (PSA_SUCCESS != res_status) {                                                                   \
            (status_out) = res_status;                                                                     \
            goto fail_label;                                                                              \
        }                                                                                                  \
    } while (0)

/*!
 * @brief Initialize the non-cryptographic PRNG for the session.
 *
 * On failure sets (status_out) and jumps to (fail_label).
 */
#define MCUXCL_INITIALIZE_PRNG(pSession, status_out, fail_label)                                           \
    do {                                                                                                   \
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("session->apiCall is not NULL")          \
        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prng_status, prng_token, mcuxClRandom_ncInit(pSession));           \
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()                                         \
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prng_token)) {                           \
            (status_out) = PSA_ERROR_CORRUPTION_DETECTED;                                                  \
            goto fail_label;                                                                              \
        }                                                                                                  \
        if (MCUXCLRANDOM_STATUS_OK != prng_status) {                                                       \
            (status_out) = PSA_ERROR_HARDWARE_FAILURE;                                                     \
            goto fail_label;                                                                              \
        }                                                                                                  \
        MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                  \
    } while (0)

/* Always allocate a minimum size RNG context buffer to avoid zero-length arrays.
 * The size is given in bytes and allocated in words. */
#define MCUXCL_PSA_ALLOCATE_RNG_CTXT(rngCtxLength) \
    ((rngCtxLength) ? (((rngCtxLength) + sizeof(uint32_t) - 1u) / sizeof(uint32_t)) : 1u)

/*!
 * @brief Allocate the RNG context, initialize the DRBG and the PRNG.
 *
 * On failure sets (status_out) and jumps to (fail_label).
 *
 * @param pSession     mcuxClSession_Handle_t for the current CL session.
 * @param rngCtxLength Size in bytes of the RNG context for the selected mode.
 * @param mode         Mode of operation for the random data generator.
 * @param status_out   lvalue of type psa_status_t updated on failure.
 * @param fail_label   label to jump to on failure (typically "cleanup").
 */
#define MCUXCL_ALLOCATE_AND_INITIALIZE_RNG(pSession, rngCtxLength, mode, status_out, fail_label)            \
    uint32_t rng_context[MCUXCL_PSA_ALLOCATE_RNG_CTXT((rngCtxLength))] = { 0 };                             \
    mcuxClRandom_Context_t pRng_ctx = (mcuxClRandom_Context_t) rng_context;                                 \
    do {                                                                                                   \
        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rng_status, rng_token,                                             \
                                         mcuxClRandom_init((pSession), pRng_ctx, (mode)));                  \
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != rng_token)) {                              \
            (status_out) = PSA_ERROR_CORRUPTION_DETECTED;                                                  \
            goto fail_label;                                                                              \
        }                                                                                                  \
        if (MCUXCLRANDOM_STATUS_OK != rng_status) {                                                        \
            (status_out) = PSA_ERROR_HARDWARE_FAILURE;                                                     \
            goto fail_label;                                                                              \
        }                                                                                                  \
        MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                  \
    } while (0);                                                                                            \
    MCUXCL_INITIALIZE_PRNG(pSession, status_out, fail_label)

#endif /* MCUXCL_PSA_ALLOCATE_CPUWA */

#ifdef __cplusplus
}
#endif


#endif /* MCUX_PSA_SGI_SESSION_HELPER_H */
