#-------------------------------------------------------------------------------
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#-------------------------------------------------------------------------------
# psa_crypto_driver: TF-M secure build logic

if(CONFIG_BUILD_WITH_TFM)

  #---------------------------------------------------------------------------
  # Common paths
  #---------------------------------------------------------------------------
  set(TFM_SOURCE_DIR            ${CMAKE_SOURCE_DIR})
  set(NXP_MODULE_CRYPTO_PATH    ${MBEDCRYPTO_PATH}/../)

  # Common PSA / mbedTLS compile definitions
  # The builtin key for initial attestation is only included if TF-M is 
  # built with initial attestation support enabled.
  set(TFM_PSA_COMPILE_DEFS
    MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED
    PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER
    $<$<BOOL:TFM_PARTITION_INITIAL_ATTESTATION>:TFM_PARTITION_INITIAL_ATTESTATION>
    MBEDTLS_CONFIG_FILE="${TFM_MBEDCRYPTO_CONFIG_PATH}"
    MBEDTLS_PSA_CRYPTO_CONFIG_FILE="${TFM_MBEDCRYPTO_PSA_CRYPTO_CONFIG_PATH}"
    $<$<BOOL:${TFM_MBEDCRYPTO_PLATFORM_EXTRA_CONFIG_PATH}>:
      MBEDTLS_USER_CONFIG_FILE="${TFM_MBEDCRYPTO_PLATFORM_EXTRA_CONFIG_PATH}">
  )
    
  #---------------------------------------------------------------------------
  # SGI PKC PSA crypto driver
  #---------------------------------------------------------------------------
  if(CONFIG_PSA_CRYPTO_DRIVER_SGI_PKC)

    add_library(McuxPsaCryptoDriverSgiPkc)
    set(NXP_MODULE_CRYPTO_PATH ${MBEDCRYPTO_PATH}/../)
    set(NXP_MODULE_SGI_PKC_PATH ${NXP_MODULE_CRYPTO_PATH}sgi_pkc)
    set(NXP_MODULE_PSA_CRYPTO_DRIVER_PATH ${NXP_MODULE_CRYPTO_PATH}psa_crypto_driver)

    target_include_directories(McuxPsaCryptoDriverSgiPkc
      PRIVATE
        # mbedTLS / PSA
        ${NXP_MODULE_CRYPTO_PATH}/mbedtls-3.6/include
        ${NXP_MODULE_CRYPTO_PATH}/mbedtls-3.6/include/psa
        ${NXP_MODULE_CRYPTO_PATH}/mbedtls-3.6/library
    )

    target_compile_definitions(McuxPsaCryptoDriverSgiPkc
      PUBLIC
        ${TFM_PSA_COMPILE_DEFS}
        PSA_CRYPTO_DRIVER_PKC
        PSA_CRYPTO_DRIVER_SGI
    )

    target_compile_options(
        McuxPsaCryptoDriverSgiPkc
        PUBLIC
            ${TOOLCHAIN_C_FLAGS}
            -mcmse   # have to explicitly add as its tfm build, not zephyr
            ${COMPILER_CP_FLAG}
    )

    target_link_options(
        McuxPsaCryptoDriverSgiPkc
        PRIVATE
            ${TOOLCHAIN_LD_FLAGS}
    )
  
    export(
      TARGETS McuxPsaCryptoDriverSgiPkc
      FILE ${CMAKE_CURRENT_BINARY_DIR}/McuxPsaCryptoDriverSgiPkcTargets.cmake
      NAMESPACE McuxPsaCryptoDriverSgiPkc::
    )

  endif()

  #---------------------------------------------------------------------------
  # ELS + PKC PSA crypto driver
  #---------------------------------------------------------------------------
  if(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC)

    add_library(McuxPsaCryptoDriverElsPkc)
    set(NXP_MODULE_CRYPTO_PATH ${MBEDCRYPTO_PATH}/../)
    set(NXP_MODULE_ELS_PKC_PATH ${NXP_MODULE_CRYPTO_PATH}/els_pkc)

    # Common TF-M include paths required, as the MBEDTLS_PSA_CRYPTO_CONFIG_FILE includes the config_tfm.h
    set(TFM_COMMON_INCLUDES
      ${TFM_SOURCE_DIR}/config
      ${TFM_SOURCE_DIR}/interface/include
      ${TFM_SOURCE_DIR}/platform/include
      ${TFM_SOURCE_DIR}/secure_fw/include
      ${TFM_SOURCE_DIR}/secure_fw/spm/include
      ${TFM_SOURCE_DIR}/secure_fw/partitions/lib/runtime/include
      ${TFM_SOURCE_DIR}/secure_fw/partitions/crypto
      ${TFM_SOURCE_DIR}/secure_fw/partitions/crypto/psa_driver_api
    )
  
    if(CONFIG_SOC_SERIES_RW6XX)
      target_include_directories(McuxPsaCryptoDriverElsPkc
        PRIVATE
          ${TFM_SOURCE_DIR}/platform/ext/target/nxp/rdrw61x
          ${TFM_SOURCE_DIR}/platform/ext/target/nxp/rdrw61x/Device/Include
          ${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver
          ${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver/drivers
      )
    endif()

    target_include_directories(McuxPsaCryptoDriverElsPkc
      PRIVATE
        ${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers/common
        ${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers/trng
        ${TFM_COMMON_INCLUDES}
    )

    target_sources(McuxPsaCryptoDriverElsPkc
      PRIVATE
        ${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers/trng/fsl_trng.c
    )

    target_compile_definitions(McuxPsaCryptoDriverElsPkc
      PRIVATE
        ${TFM_PSA_COMPILE_DEFS}
    )

    target_compile_options(
        McuxPsaCryptoDriverElsPkc
        PUBLIC
            ${TOOLCHAIN_C_FLAGS}
            -mcmse   # have to explicitly add as its tfm build, not zephyr
    )
     target_compile_options(
        McuxPsaCryptoDriverElsPkc
        PUBLIC
            ${COMPILER_CP_FLAG}
    )
    target_link_options(
        McuxPsaCryptoDriverElsPkc
        PRIVATE
            ${TOOLCHAIN_LD_FLAGS}
    )

    export(
      TARGETS McuxPsaCryptoDriverElsPkc
      FILE ${CMAKE_CURRENT_BINARY_DIR}/McuxPsaCryptoDriverElsPkcTargets.cmake
      NAMESPACE McuxPsaCryptoDriverElsPkc::
    )

  endif()

endif()