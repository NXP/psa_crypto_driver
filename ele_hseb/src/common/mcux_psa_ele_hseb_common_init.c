/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_ele_hseb_common_init.h"
#include "hse_mu.h"

/******************************************************************************/
/*************************** Mutex ********************************************/
/******************************************************************************/
/*
 * Define global mutexes for HW accelerator
 */
mcux_mutex_t ele_hseb_hwcrypto_mutex;

/******************************************************************************/
/******************** CRYPTO_InitHardware *************************************/
/******************************************************************************/

static bool is_key_catalog_formatted(void)
{
    return CHECK_HSE_STATUS(HSE_STATUS_INSTALL_OK);
}

static bool is_hse_ready(void)
{
    return CHECK_HSE_STATUS(HSE_STATUS_INIT_OK);
}


bool g_isCryptoHWInitialized = false;

/*!
 * @brief Application init for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t result = kStatus_Fail;

    if (true == g_isCryptoHWInitialized) {
        return kStatus_Success;
    }

    /* Mutex for access to ele_crypto HW */
    if (mcux_mutex_init(&ele_hseb_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    if (mcux_mutex_lock(&ele_hseb_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    do {
        if (is_hse_ready() == false) {
            result = kStatus_Fail;
            break;
        }

        /* Key catalogs MUST be formatted by the user. Formatting deletes keys,
         * so it cannot be done during PSA init to prevent possibly losing
         * keys set previously.
         */
        if (is_key_catalog_formatted() == false) {
            result = kStatus_Fail;
            break;
        }

        result = kStatus_Success;
        g_isCryptoHWInitialized = true;
    } while (0);

    if (mcux_mutex_unlock(&ele_hseb_hwcrypto_mutex) != 0) {
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
    if (false == g_isCryptoHWInitialized) {
        return kStatus_Success;
    }

    g_isCryptoHWInitialized = false;

    (void) mcux_mutex_free(&ele_hseb_hwcrypto_mutex);

    return kStatus_Success;
}


/*!
 * @brief Application Reinit for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic reinit for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_ReinitHardware(void)
{
    /* Reset the init state so the hardware will be reinitialized at the next cryptographic HW acceleration operation */
    g_isCryptoHWInitialized = false;

    return kStatus_Success;
}
