/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_sgi_common_init.h"

#include <mcuxClResource.h>

/******************************************************************************/
/*************************** Mutex ********************************************/
/******************************************************************************/
/*
 * Define global mutexes for HW accelerator
 */
mcux_mutex_t sgi_hwcrypto_mutex;

/******************************************************************************/
/*********************** Single resource context *****************************/
/******************************************************************************/
/*
 * Access is serialized by the per-block HW mutex (sgi_hwcrypto_mutex /
 * pkc_hwcrypto_mutex), which every driver entry point holds while a session is
 * active, so no additional locking is required here.
 */
static uint32_t s_psa_resource_ctx[MCUXCLRESOURCE_CONTEXT_SIZE / sizeof(uint32_t)];

psa_status_t mcux_psa_session_set_resource(mcuxClSession_Handle_t session)
{
    mcuxClResource_Context_t *pResourceCtx = (mcuxClResource_Context_t *) s_psa_resource_ctx;

    /*
     * Re-initialize the shared resource context for every session.
     *
     * The resource context memory is a single static instance (never stack
     * allocated per call), but it must be re-initialized before it is bound to
     * each new mcuxClSession. Each driver entry point creates a fresh session
     * and calls mcuxClSession_destroy() on cleanup, which releases the resource
     * context's HW arbitration state.
     */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ri_status, ri_token, mcuxClResource_init(
        /* mcuxClResource_Context_t * pResourceCtx:              */ pResourceCtx,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
        /* mcuxClResource_MutexAcquire_Callback_t pMutexAcquire: */ NULL,
        /* mcuxClResource_MutexRelease_Callback_t pMutexRelease: */ NULL
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    ));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_init) != ri_token)
        || (MCUXCLRESOURCE_STATUS_OK != ri_status)) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ssr_status, ssr_token,
                                     mcuxClSession_setResource(session, pResourceCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_setResource) != ssr_token)
        || (MCUXCLSESSION_STATUS_OK != ssr_status)) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return PSA_SUCCESS;
}

/******************************************************************************/
/******************** CRYPTO_InitHardware *************************************/
/******************************************************************************/

uint32_t g_isCryptoHWInitialized = false;

/*!
 * @brief Application init for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t result = kStatus_Fail;

    if (g_isCryptoHWInitialized == true) {
        return kStatus_Success;
    }

    /* Mutex for access to sgi crypto HW */
    if (mcux_mutex_init(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    result = CRYPTO_InitHardwareUnsafe();

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    return result;
}

/*!
 * @brief Application init for Crypto blocks.
 *
 * Unsafe version of CRYPTO_InitHardware that does not take mutexs.
 *
 * @warning This function does not acquire any mutex locks and is not thread-safe.
 *          If called incorrectly by an application (e.g., from multiple threads
 *          concurrently or without proper external synchronization), this may
 *          cause race conditions, undefined behavior, or hardware access issues.
 *          Use CRYPTO_InitHardware() for thread-safe initialization.
 */
status_t CRYPTO_InitHardwareUnsafe(void)
{
    status_t result = kStatus_Fail;

    if (g_isCryptoHWInitialized == true) {
        return kStatus_Success;
    }

    /* Enable SGI and related HW */
    result = SGI_PowerDownWakeupInit(SGI0);
    if (result == kStatus_Success) {
        g_isCryptoHWInitialized = true;
    }

    return result;
}

/*!
 * @brief Application Deinit for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic deinit for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_DeinitHardware(void)
{
    status_t result = kStatus_Fail;

    if (g_isCryptoHWInitialized == false) {
        return kStatus_Success;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    result = kStatus_Success;
    g_isCryptoHWInitialized = false;

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    if (result == kStatus_Success) {
        if (mcux_mutex_free(&sgi_hwcrypto_mutex) != 0) {
            return kStatus_Fail;
        }
    }

    return result;
}

/*!
 * @brief Application Deinit for Crypto blocks.
 *
 * Unsafe version of CRYPTO_DeinitHardware that does not take mutexs and do not close handles.
 *
 * @warning This function does not acquire any mutex locks and is not thread-safe.
 *          If called incorrectly by an application (e.g., from multiple threads
 *          concurrently or without proper external synchronization), this may
 *          cause race conditions, undefined behavior, or hardware access issues.
 *          Use CRYPTO_DeinitHardware() for thread-safe de-initialization.
 */
status_t CRYPTO_DeinitHardwareUnsafe(void)
{
    if (g_isCryptoHWInitialized == false) {
        return kStatus_Success;
    }

    g_isCryptoHWInitialized = false;

    return kStatus_Success;
}
