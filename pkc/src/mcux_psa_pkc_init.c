/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_pkc_init.h" /* PKC Crypto port layer */


#include "fsl_crc.h"
#include "fsl_trng.h"
#include "fsl_glikey.h"

/******************************************************************************/
/*************************** Mutex ********************************************/
/******************************************************************************/
/*
 * Define global mutexes for HW accelerator
 */
mcux_mutex_t pkc_hwcrypto_mutex;

/******************************************************************************/
/******************** CRYPTO_InitHardware *************************************/
/******************************************************************************/

bool g_isPkcHWInitialized = false;

/*!
 * @brief Application init for the PKC crypto block.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t psa_pkc_init(void)
{
    status_t status = kStatus_Fail;

    if (g_isPkcHWInitialized == true) {
        return kStatus_Success;
    }

    /* Mutex for access to pkc_crypto HW */
    if (mcux_mutex_init(&pkc_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    if (mcux_mutex_lock(&pkc_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    do {
        RESET_ReleasePeripheralReset(kPKC0_RST_SHIFT_RSTn);

        RESET_ReleasePeripheralReset(kTRNG0_RST_SHIFT_RSTn);

        CLOCK_EnableClock(kCLOCK_GateSGI0);

        CLOCK_EnableClock(kCLOCK_GateTRNG0);

        CLOCK_EnableClock(kCLOCK_GatePKC0);

        trng_config_t trngcon;
        status = TRNG_GetDefaultConfig(&trngcon);
        if (kStatus_Success != status) {
            break;
        }
        trngcon.oscillatorMode = kTRNG_DualOscillatorMode;

        status = TRNG_Init(TRNG0, &trngcon);
        if (kStatus_Success != status) {
            break;
        }

        CRC_Type *base = CRC0;
        crc_config_t config;
        CRC_GetDefaultConfig(&config);
        CRC_Init(base, &config);

        status = kStatus_Success;
        g_isPkcHWInitialized = true;
    } while (false);

    if (mcux_mutex_unlock(&pkc_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    return status;
}

/*!
 * @brief Application Deinit for the PKC crypto block.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic deinit for Crypto Hw acceleration and Hw entropy modules.
 */
status_t psa_pkc_deinit(void)
{
    status_t result = kStatus_Fail;

    if (g_isPkcHWInitialized == false) {
        return kStatus_Success;
    }

    if (mcux_mutex_lock(&pkc_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    do {
        RESET_SetPeripheralReset(kPKC0_RST_SHIFT_RSTn);
        CLOCK_DisableClock(kCLOCK_GatePKC0);

        result = kStatus_Success;
        g_isPkcHWInitialized = false;
    } while (false);

    if (mcux_mutex_unlock(&pkc_hwcrypto_mutex) != 0) {
        return kStatus_Fail;
    }

    (void) mcux_mutex_free(&pkc_hwcrypto_mutex);

    return result;
}
