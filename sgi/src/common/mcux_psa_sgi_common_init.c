/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_sgi_common_init.h" /* ELE Crypto port layer */


/******************************************************************************/
/*************************** Mutex ********************************************/
/******************************************************************************/
/*
 * Define global mutexes for HW accelerator
 */
mcux_mutex_t sgi_hwcrypto_mutex;

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
        return 0;
    }

    /* Mutex for access to sgi crypto HW */
    if (mcux_mutex_init(&sgi_hwcrypto_mutex) != 0) {
        PRINTF("NO memory - init failed\n");
        return kStatus_Fail;
    }

    if ((result = mcux_mutex_lock(&sgi_hwcrypto_mutex)) != 0) {
        PRINTF("Mutex lock failed\n");
        return kStatus_Fail;
    }

    do {
        result = kStatus_Success;

        g_isCryptoHWInitialized = true;

    } while (0);


    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        PRINTF("Mutex unlock failed\n");
        return kStatus_Fail;
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
        return 0;
    }

    if (mcux_mutex_lock(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    if (result == kStatus_Success) {
        g_isCryptoHWInitialized = false;
    }

    if (mcux_mutex_unlock(&sgi_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    if (result == kStatus_Success) {
        (void) mcux_mutex_free(&sgi_hwcrypto_mutex);
    }

    return result;
}
