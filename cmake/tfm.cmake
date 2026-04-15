#-------------------------------------------------------------------------------
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# TF-M secure build logic
message ("psa-crypto-driver-els-pkc tf-m cmake included.")

add_library(McuxPsaCryptoDriverElsPkc)
set(NXP_MODULE_CRYPTO_PATH ${MBEDCRYPTO_PATH}/../)
set(NXP_MODULE_ELS_PKC_PATH ${NXP_MODULE_CRYPTO_PATH}/els_pkc)

if(CONFIG_SOC_SERIES_RW6XX)
	
	set(TFM_SOURCE_DIR ${CMAKE_SOURCE_DIR})
	target_include_directories(McuxPsaCryptoDriverElsPkc
		PRIVATE
			${TFM_SOURCE_DIR}/platform/ext/target/nxp/rdrw61x
			${TFM_SOURCE_DIR}/platform/ext/target/nxp/rdrw61x/Device/Include
			# SDK driver header files path of rw61x
			${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver
			${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver/drivers
	)
endif()

#dependency coming from tfm_mbedcrypto_config and it has #include "config_tfm.h"
target_include_directories(McuxPsaCryptoDriverElsPkc
	PRIVATE
		# SDK driver header files path
		${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers/common
		${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers/trng

		##tf-m src include paths
		${TFM_SOURCE_DIR}/config
		${TFM_SOURCE_DIR}/interface/include
		${TFM_SOURCE_DIR}/platform/include
		${TFM_SOURCE_DIR}/secure_fw/include
		${TFM_SOURCE_DIR}/secure_fw/spm/include
		${TFM_SOURCE_DIR}/secure_fw/partitions/lib/runtime/include
		${TFM_SOURCE_DIR}/secure_fw/partitions/crypto
		${TFM_SOURCE_DIR}/secure_fw/partitions/crypto/psa_driver_api
)

target_sources(
	McuxPsaCryptoDriverElsPkc 
	PRIVATE
		# SDK driver files
		${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers/trng/fsl_trng.c
)

target_compile_definitions(
	McuxPsaCryptoDriverElsPkc 
	PRIVATE
	    MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED
		PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER
		# The builtin key for initial attestation is only included if TF-M is 
		# built with initial attestation support enabled.
		$<$<BOOL:TFM_PARTITION_INITIAL_ATTESTATION>:TFM_PARTITION_INITIAL_ATTESTATION>
		MBEDTLS_CONFIG_FILE="${TFM_MBEDCRYPTO_CONFIG_PATH}"
		MBEDTLS_PSA_CRYPTO_CONFIG_FILE="${TFM_MBEDCRYPTO_PSA_CRYPTO_CONFIG_PATH}"
		$<$<BOOL:${TFM_MBEDCRYPTO_PLATFORM_EXTRA_CONFIG_PATH}>:MBEDTLS_USER_CONFIG_FILE="${TFM_MBEDCRYPTO_PLATFORM_EXTRA_CONFIG_PATH}">
)	

# Export target for TF-M consumption
export(
    TARGETS McuxPsaCryptoDriverElsPkc
    FILE ${CMAKE_CURRENT_BINARY_DIR}/McuxPsaCryptoDriverElsPkcTargets.cmake
    NAMESPACE McuxPsaCryptoDriverElsPkc::
)
