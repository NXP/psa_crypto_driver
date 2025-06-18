#-------------------------------------------------------------------------------
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
set(PSA_CRYPTO_DRIVER_PATH ${CMAKE_CURRENT_LIST_DIR}/../)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

string(TOUPPER ${CONFIG_SOC} MCUX_DEVICE)

if(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC AND NOT CONFIG_BUILD_WITH_TFM)
    message ("psa-crypto-driver module is included.")
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../ psa_crypto_driver)
    zephyr_include_directories("$<TARGET_PROPERTY:McuxPsaCryptoDriverElsPkc,INTERFACE_INCLUDE_DIRECTORIES>")
    target_link_libraries(app PUBLIC McuxPsaCryptoDriverElsPkc)
endif()

if(CONFIG_PSA_CRYPTO_DRIVER_DCP)

    message ("psa-crypto-driver-dcp module is included.")

    add_library(McuxPsaCryptoDriverDcp)

    target_link_options(
        McuxPsaCryptoDriverDcp
        PRIVATE
            ${TOOLCHAIN_LD_FLAGS}
    )

    target_compile_definitions(
        McuxPsaCryptoDriverDcp
        PUBLIC
           CPU_MIMXRT1062DVL6A
    )
        target_compile_definitions(
        McuxPsaCryptoDriverDcp
        PRIVATE
            MBEDTLS_MCUX_ENTROPY
    )

    target_compile_definitions(
        McuxPsaCryptoDriverDcp
        PRIVATE
            MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED
    )

    target_include_directories(
        McuxPsaCryptoDriverDcp
        PRIVATE
            # SDK driver header files
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/common
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/trng
            # zephyr includes for mutex functions for psa-crypto-driver
            ${CMAKE_CURRENT_LIST_DIR}/osal/zephyr
            ${CMAKE_CURRENT_LIST_DIR}/osal/.
            # include zephyr directories include path
            "$<TARGET_PROPERTY:zephyr,INTERFACE_INCLUDE_DIRECTORIES>"
    )

    target_include_directories(
        McuxPsaCryptoDriverDcp
        PUBLIC
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/dcp/
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/devices/RT/RT1060/periph/
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/rng/
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/include/
            ${PSA_CRYPTO_DRIVER_PATH}/osal/
            ${PSA_CRYPTO_DRIVER_PATH}/osal/zephyr
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/../../../zsdk/samples/crypto/nxp_mbedtls_configs/
     )

    target_sources(
         McuxPsaCryptoDriverDcp
         PRIVATE
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/dcp.h
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/dcp_crypto_primitives.h
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/include/mcux_psa_dcp_cipher.h
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/include/mcux_psa_dcp_common_init.h
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/include/mcux_psa_dcp_entropy.h
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/include/mcux_psa_dcp_hash.h
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/src/mcux_psa_dcp_cipher.c
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/src/mcux_psa_dcp_common_init.c
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/src/mcux_psa_dcp_entropy.c
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/src/mcux_psa_dcp_hash.c
            ${PSA_CRYPTO_DRIVER_PATH}/dcp/src/mcux_psa_dcp_init.c
            ${PSA_CRYPTO_DRIVER_PATH}/osal/osal_mutex.h
            ${PSA_CRYPTO_DRIVER_PATH}/osal/zephyr/osal_mutex_platform.h
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/../../../zsdk/samples/crypto/nxp_mbedtls_configs/mcux_mbedtls_config.h
    )
    add_dependencies(McuxPsaCryptoDriverDcp zephyr_interface)

    target_sources(
        McuxPsaCryptoDriverDcp
        PRIVATE
            # SDK driver files
            ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/trng/fsl_trng.c
    )

    target_compile_options(
        McuxPsaCryptoDriverDcp
        PRIVATE
            "$<TARGET_PROPERTY:zephyr_interface,INTERFACE_COMPILE_OPTIONS>"
    )

    target_compile_definitions(
        McuxPsaCryptoDriverDcp
        PRIVATE
            PSA_CRYPTO_DRIVER_THREAD_EN
            __ZEPHYR__
            PSA_CRYPTO_DRIVER_DCP
            $<$<BOOL:${CONFIG_MBEDTLS_USER_CONFIG_FILE}>:MBEDTLS_USER_CONFIG_FILE="${CONFIG_MBEDTLS_USER_CONFIG_FILE}">
            MBEDTLS_CONFIG_FILE="${ZEPHYR_HAL_NXP_MODULE_DIR}/../../../zsdk/samples/crypto/nxp_mbedtls_configs/mcux_mbedtls_config.h"
    )

export(TARGETS McuxPsaCryptoDriverDcp
    FILE "${CMAKE_CURRENT_BINARY_DIR}/McuxPsaCryptoDriverDcpTargets.cmake"
    NAMESPACE McuxPsaCryptoDriverDcp::
)
endif()
