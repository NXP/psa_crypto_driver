/*
 * Copyright 2025-2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_ele_hseb_common_init.h"
#include "hse_mu.h"
#include "hse_interface.h"
#include "hse_host_format_key_catalogs.h"
#include "hse_host_import_key.h"
#include "hse_keys_allocator.h"
#include <string.h>

#if defined(CONFIG_ELE_HSEB_CUSTOM_CONFIG_HEADER)
#include CONFIG_ELE_HSEB_CUSTOM_CONFIG_HEADER
#else
#include "hse_default_config.h"
#endif

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

#if defined(CONFIG_ELE_HSEB_AUTOFORMAT_KEY_CATALOGS)
/**
 * @brief Sync the host NVM key mirror with HSE-B internal state after a PoR.
 * @details HKF_Init() rebuilds the mirror topology but marks all slots empty.
 *          This function probes every NVM slot via HSE_SRV_ID_GET_KEY_INFO and
 *          marks occupied slots with HKF_MarkAsAllocated(), restoring the mirror
 *          to match the persisted HSE-B internal state.
 *          Call this once after HKF_Init(), when the catalog was already formatted.
 */
static hseSrvResponse_t sync_nvm_key_mirror(const hseKeyGroupCfgEntry_t *pNvmCatalog)
{
    hseSrvResponse_t status = HSE_SRV_RSP_OK;
    hseKeyGroupIdx_t group_id;
    hseKeySlotIdx_t  slot_id;

    for (group_id = 0u;; ++group_id) {
        if (pNvmCatalog[group_id].muMask        == 0u &&
            pNvmCatalog[group_id].groupOwner    == 0u &&
            pNvmCatalog[group_id].keyType       == 0u &&
            pNvmCatalog[group_id].numOfKeySlots == 0u &&
            pNvmCatalog[group_id].maxKeyBitLen  == 0u) {
            /* Zero-terminator reached */
            break;
        }

        for (slot_id = 0u; slot_id < pNvmCatalog[group_id].numOfKeySlots; ++slot_id) {
            hseKeyHandle_t handle = GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, group_id, slot_id);
            hseKeyInfo_t   keyInfo;
            hseSrvResponse_t rsp;

            (void) memset(&keyInfo, 0, sizeof(keyInfo));
            rsp = GetKeyInfo(handle, &keyInfo);

            if (HSE_SRV_RSP_OK == rsp) {
                /* Slot is occupied - mark it in the host mirror */
                (void) HKF_MarkAsAllocated(handle);
            } else if (HSE_SRV_RSP_KEY_EMPTY == rsp) {
                /* Slot is empty - mirror is already correct */
            } else {
                status = rsp;
                goto exit;
            }
        }
    }

exit:
    return status;
}
#endif /* CONFIG_ELE_HSEB_AUTOFORMAT_KEY_CATALOGS */

static bool is_key_catalog_formatted(void)
{
    return CHECK_HSE_STATUS(HSE_STATUS_INSTALL_OK);
}

static bool is_hse_ready(void)
{
    return CHECK_HSE_STATUS(HSE_STATUS_INIT_OK);
}

bool g_isCryptoHWInitialized = false;

#if defined(CONFIG_ELE_HSEB_AUTOFORMAT_KEY_CATALOGS)
/* coverity[cert_arr30_c_violation] coverity[cert_str31_c_violation] coverity[overrun-buffer-val] : intentional - vendor-defined catalog macros */
static const hseKeyGroupCfgEntry_t nvmKeyCatalog[] = { HSE_NVM_KEY_CATALOG_CFG };
/* coverity[cert_arr30_c_violation] coverity[cert_str31_c_violation] coverity[overrun-buffer-val] : intentional - vendor-defined catalog macros */
static const hseKeyGroupCfgEntry_t ramKeyCatalog[] = { HSE_RAM_KEY_CATALOG_CFG };
#endif

/*!
 * @brief Application init for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t result = kStatus_Fail;
#if defined(CONFIG_ELE_HSEB_AUTOFORMAT_KEY_CATALOGS)
    hseSrvResponse_t result_fmt = HSE_SRV_RSP_GENERAL_ERROR;
    hseSrvResponse_t result_hkf = HSE_SRV_RSP_GENERAL_ERROR;
    hseSrvResponse_t result_sync = HSE_SRV_RSP_GENERAL_ERROR;
#endif

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

        /* Key catalogs MUST be formatted prior to using cryptography features.
         * Formatting deletes keys, so we do it only if configured to do so.
         * Otherwise we just check if formatting was done by the user.
         */
#if defined(CONFIG_ELE_HSEB_AUTOFORMAT_KEY_CATALOGS)
        /* Formatting may have been done before a power cycle. In order to preserve
         * persistent keys (those that are in the NVM key catalog), we check
         * if formatting is already done. If yes, we skip reformatting, so we don't
         * delete them.
         */
        if (is_key_catalog_formatted() == false) {
            result_fmt = FormatKeyCatalogs(nvmKeyCatalog, ramKeyCatalog);
        } else {
            /* Catalog is formatted, we assume an OK */
            result_fmt = HSE_SRV_RSP_OK;
        }
        /* We set up the runtime mirror. HKF_Init() sets up the mirror and
         * sync_nvm_key_mirror() syncs the NVM runtime catalog mirror with
         * already-occupied key slots (persistent keys).
         */
        result_hkf = HKF_Init(nvmKeyCatalog, ramKeyCatalog);
        result_sync = sync_nvm_key_mirror(nvmKeyCatalog);
        if (HSE_SRV_RSP_OK != result_fmt ||
            HSE_SRV_RSP_OK != result_hkf ||
            HSE_SRV_RSP_OK != result_sync) {
            result = kStatus_Fail;
            break;
        }
#endif
        if (is_key_catalog_formatted() == false) {
            result = kStatus_Fail;
            break;
        }

        result = kStatus_Success;
        g_isCryptoHWInitialized = true;
    } while (false);

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
    /* Reset the init state so the hardware will be reinitialized at the next
     * cryptographic HW acceleration operation.
     */
    g_isCryptoHWInitialized = false;

    return kStatus_Success;
}
