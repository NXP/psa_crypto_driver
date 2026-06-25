#-------------------------------------------------------------------------------
# Copyright 2023-2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if(NOT CONFIG_BUILD_WITH_TFM)
	find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
endif()

if(CONFIG_PSA_CRYPTO_DRIVER_CASPER_HASHCRYPT)
	message ("psa-crypto-driver-casper_hashcrypt module is included.")

	zephyr_library_named(McuxPsaDrvCasperHc)

	# This ensures that even zephyr part will see these defines (e.g. MbedTLS module)
	zephyr_compile_definitions(
		PSA_CRYPTO_DRIVER_CASPER
		PSA_CRYPTO_DRIVER_HASHCRYPT
		PSA_CRYPTO_DRIVER_THREAD_EN
	)

	### IP Drivers ###
	target_include_directories(
		McuxPsaDrvCasperHc
		PUBLIC
		# Hashcrypt and CASPER drivers
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/casper
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/hashcrypt
	)


	target_sources(
		McuxPsaDrvCasperHc
		PRIVATE
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/casper/fsl_casper.c
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/hashcrypt/fsl_hashcrypt.c
	)


	### MbedTLS ###
	target_include_directories(
		McuxPsaDrvCasperHc
		PUBLIC
		# PSA crypto headers
		${ZEPHYR_BASE}/modules/mbedtls/configs
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/include
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/library
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/include/psa
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/include/mbedtls
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/pqcp/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/dispatch
		# tf-psa-crypto core headers (e.g. psa_crypto_random_impl.h)
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/core
		# Private MbedTLS headers required by casper driver sources that use
		# bare includes (e.g. #include "ecp.h", #include "ecdsa.h",
		# #include "hmac_drbg.h"). These live under the tf-psa-crypto private
		# directory. Also add the mbedtls/ parent so that bare includes like
		# #include "private_access.h" (which sits directly in mbedtls/) resolve.
		# Added here per-target to avoid enabling the global
		# CONFIG_MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS option.
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/include/mbedtls
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/include/mbedtls/private
	)


	### PSA Crypto Driver ###

	# PSA driver include paths
	target_include_directories(
		McuxPsaDrvCasperHc
		PUBLIC
		${PSA_CRYPTO_DRIVER_PATH}/casper/
		${PSA_CRYPTO_DRIVER_PATH}/casper/include
		${PSA_CRYPTO_DRIVER_PATH}/casper/common/include
		${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/
		${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/include
		${PSA_CRYPTO_DRIVER_PATH}/osal/
		${PSA_CRYPTO_DRIVER_PATH}/osal/zephyr/
	)

	# PSA driver implementation
	target_sources(
		McuxPsaDrvCasperHc
		PRIVATE
		# Source
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_common_asymmetric_signature.c
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_common_init.c
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_ecdh_port.c
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_ecdsa_port.c
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_ecp_port.c
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_init.c
		${PSA_CRYPTO_DRIVER_PATH}/casper/src/mcux_psa_casper_key_generation_port.c
        ${PSA_CRYPTO_DRIVER_PATH}/casper/common/src/mcux_psa_common_key_management.c
        ${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/src/mcux_psa_hashcrypt_common_cipher.c
        ${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/src/mcux_psa_hashcrypt_common_init.c
        ${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/src/mcux_psa_hashcrypt_entropy.c
        ${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/src/mcux_psa_hashcrypt_hash.c
        ${PSA_CRYPTO_DRIVER_PATH}/hashcrypt/src/mcux_psa_hashcrypt_init.c
	)

	# Adding OSAL for Zephyr Mutexes
	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/osal)

	target_link_libraries(McuxPsaDrvCasperHc PUBLIC zephyr_interface)
	target_link_libraries(McuxPsaDrvCasperHc PUBLIC mbedTLS tfpsacrypto builtin)
	# The casper driver uses the legacy mbedTLS C API (mbedtls_mpi_*, mbedtls_ecp_*).
	# These symbols are compiled into the 'builtin' target only when the legacy
	# MBEDTLS_ECP_C / MBEDTLS_BIGNUM_C symbols are defined.  With mbedTLS 4.x /
	# TF-PSA-Crypto driver stubs them out unless we opt back in.
	#
	# We inject the defines via -include with #ifndef guards instead of bare -D
	# command-line defines. If another build path (e.g. crypto_adjust_config_enable_builtins.h)
	# already defines these macros the #ifndef guards resolve redefinition issue.
	# zephyr_compile_options() propagates the flag to all Zephyr
	# targets (including 'builtin' and 'tfpsacrypto').
	zephyr_compile_options(
		-include ${PSA_CRYPTO_DRIVER_PATH}/casper/casper_ecp_legacy_config.h
	)

endif() # CONFIG_PSA_CRYPTO_DRIVER_CASPER_HASHCRYPT #
if(CONFIG_PSA_CRYPTO_DRIVER_SGI_PKC)
	message ("psa-crypto-driver-sgi_pkc module is included.")

if( CONFIG_BUILD_WITH_TFM)
	include(${CMAKE_CURRENT_LIST_DIR}/cmake/tfm.cmake)
else()
	zephyr_library_named(McuxPsaCryptoDriverSgiPkc)
	set(NXP_MODULE_CRYPTO_PATH ${ZEPHYR_MBEDTLS_MODULE_DIR}/../)
	set(NXP_MODULE_SGI_PKC_PATH ${ZEPHYR_SGI_PKC_MODULE_DIR})
	set(NXP_MODULE_PSA_CRYPTO_DRIVER_PATH ${ZEPHYR_PSA_CRYPTO_DRIVER_MODULE_DIR})

	# This ensures that even zephyr part will see these defines (e.g. MbedTLS module)
	zephyr_compile_definitions(
		PSA_CRYPTO_DRIVER_SGI
		PSA_CRYPTO_DRIVER_PKC
		PSA_CRYPTO_DRIVER_THREAD_EN
		MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED
	)


	# HW drivers (dependency for Crypto IP/Clib)
	target_include_directories(
		McuxPsaCryptoDriverSgiPkc
		PUBLIC
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/trng
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/glikey
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/crc
	)

	target_sources(
		McuxPsaCryptoDriverSgiPkc
		PRIVATE
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/trng/fsl_trng.c
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/glikey/fsl_glikey.c
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/crc/fsl_crc.c
	)

	target_include_directories(McuxPsaCryptoDriverSgiPkc
		PRIVATE
		# psa/crypto.h and psa/crypto_types.h
		${NXP_MODULE_CRYPTO_PATH}/mbedtls/include
		${NXP_MODULE_CRYPTO_PATH}/mbedtls/include/psa
		# for psa driver wrapper
		${NXP_MODULE_CRYPTO_PATH}/mbedtls/library
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/core
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/pqcp/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/dispatch
	)

endif()

	### PSA Crypto Driver ###

	# SGI PSA driver include paths
	target_include_directories(
		McuxPsaCryptoDriverSgiPkc
		PUBLIC
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/common
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/transparent
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/osal/
		"$<TARGET_PROPERTY:McuxSgiPkc,INTERFACE_INCLUDE_DIRECTORIES>"
	)

	# SGI PSA driver implementation
	target_sources(
		McuxPsaCryptoDriverSgiPkc
		PRIVATE
		# Source
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/common/mcux_psa_sgi_common_init.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/common/mcux_psa_sgi_entropy.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/transparent/mcux_psa_sgi_aead.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/transparent/mcux_psa_sgi_cipher.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/transparent/mcux_psa_sgi_hash.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/transparent/mcux_psa_sgi_init.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/src/transparent/mcux_psa_sgi_mac.c
		# Include
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/common/mcux_psa_sgi_common_init.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/common/mcux_psa_sgi_entropy.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/transparent/mcux_psa_sgi_cipher.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/transparent/mcux_psa_sgi_aead.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/transparent/mcux_psa_sgi_hash.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/transparent/mcux_psa_sgi_init.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/sgi/include/transparent/mcux_psa_sgi_mac.h
	)

	# PKC PSA driver include paths
	target_include_directories(
		McuxPsaCryptoDriverSgiPkc
		PUBLIC
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/include
	)

	# PKC PSA driver implementation
	target_sources(
		McuxPsaCryptoDriverSgiPkc
		PRIVATE
		# Source
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/src/mcux_psa_pkc_asymmetric_signature.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/src/mcux_psa_pkc_init.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/src/mcux_psa_pkc_utils.c
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/src/mcux_psa_pkc_key_generation.c
		# Include
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/pkc.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/include/mcux_psa_pkc_asymmetric_signature.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/include/mcux_psa_pkc_init.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/include/mcux_psa_pkc_utils.h
		${NXP_MODULE_PSA_CRYPTO_DRIVER_PATH}/pkc/include/mcux_psa_pkc_key_generation.h
	)

	#link with McuxSgiPkc library
	target_link_libraries(McuxPsaCryptoDriverSgiPkc PUBLIC McuxSgiPkc)

	# Adding OSAL for Zephyr Mutexes
	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/osal)
	
if( NOT CONFIG_BUILD_WITH_TFM)

	# We must ensure we link this library into zephyr_interface, 
	# otherwise we won't get compile options defined in Zephyr
	target_link_libraries(McuxPsaCryptoDriverSgiPkc PUBLIC zephyr_interface)
endif()


endif() # CONFIG_PSA_CRYPTO_DRIVER_SGI_PKC #

if(CONFIG_PSA_CRYPTO_DRIVER_ELE_S4xx)
	message ("psa-crypto-driver-ele_s4xx module is included.")

	# Creating new library
	zephyr_library_named(McuxPsaCryptoDriverEleS4xx)

	# This ensures that even zephyr part will see these defines (e.g. MbedTLS module)
	zephyr_compile_definitions(
		PSA_CRYPTO_DRIVER_ELE_S4XX
		PSA_CRYPTO_DRIVER_THREAD_EN
		ELE_CACHE_HANDLING
	)

	### ELE Crypto ###
	target_include_directories(
		McuxPsaCryptoDriverEleS4xx
		PUBLIC
		# ELE Crypto header files
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/ele_crypto/
	)

	target_sources(
		McuxPsaCryptoDriverEleS4xx
		PRIVATE
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/ele_crypto/ele_crypto_internal.h
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/ele_crypto/ele_nvm_manager.c	
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/ele_crypto/ele_nvm_manager.h
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/ele_crypto/ele_crypto.h
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/ele_crypto/ele_crypto.c
	)


	### MbedTLS ###
	target_include_directories(
		McuxPsaCryptoDriverEleS4xx
		PUBLIC
		# PSA crypto headers
		${ZEPHYR_BASE}/modules/mbedtls/configs
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/include
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/library
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/include/psa
		${ZEPHYR_BASE}/../modules/crypto/mbedtls/include/mbedtls
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/pqcp/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/dispatch
	)


	### PSA Crypto Driver ###
	
	# PSA driver include paths
	target_include_directories(
		McuxPsaCryptoDriverEleS4xx
		PUBLIC
		${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/
		${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/common
		${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent
		${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque
		${PSA_CRYPTO_DRIVER_PATH}/osal/
		${PSA_CRYPTO_DRIVER_PATH}/osal/zephyr/
	)

	# PSA driver implementation
	target_sources(
		McuxPsaCryptoDriverEleS4xx
		PRIVATE
		# Source
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/common/mcux_psa_s4xx_common_init.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/common/mcux_psa_s4xx_common_key_management.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/common/mcux_psa_s4xx_entropy.c
        # ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/common/mcux_psa_s4xx_sdmmc_nvm_manager.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/common/mcux_psa_s4xx_zephyr_nvm_manager.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/transparent/mcux_psa_s4xx_asymmetric_signature.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/transparent/mcux_psa_s4xx_init.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/transparent/mcux_psa_s4xx_aead.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/transparent/mcux_psa_s4xx_hash.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/transparent/mcux_psa_s4xx_cipher.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/transparent/mcux_psa_s4xx_asymmetric_encryption.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_aead.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_asymmetric_signature.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_cipher.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_init.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_key_generation.c
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_mac.c
        
        # Include
		${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/ele_s4xx_crypto_primitives.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/common/mcux_psa_s4xx_common_init.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/common/mcux_psa_s4xx_common_key_management.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/common/mcux_psa_s4xx_entropy.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/common/mcux_psa_s4xx_sdmmc_nvm_manager.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent/mcux_psa_s4xx_init.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent/mcux_psa_s4xx_hash.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent/mcux_psa_s4xx_aead.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent/mcux_psa_s4xx_cipher.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent/mcux_psa_s4xx_asymmetric_encryption.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/transparent/mcux_psa_s4xx_asymmetric_signature.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_aead.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_asymmetric_signature.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_cipher.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_init.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_key_generation.h
        ${PSA_CRYPTO_DRIVER_PATH}/ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_mac.h
	)

	# Adding OSAL for Zephyr Mutexes
	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/osal)

	# We must ensure we link this library into zephyr_interface, 
	# otherwise we won't get compile options defined in Zephyr
	target_link_libraries(McuxPsaCryptoDriverEleS4xx PUBLIC zephyr_interface)

endif() # CONFIG_PSA_CRYPTO_DRIVER_ELE_S4xx #

if(CONFIG_PSA_CRYPTO_DRIVER_DCP)

	message ("psa-crypto-driver-dcp module is included.")

	zephyr_library_named(McuxPsaCryptoDriverDcp)

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

	zephyr_compile_definitions(
		PSA_CRYPTO_DRIVER_DCP
		PSA_CRYPTO_DRIVER_THREAD_EN
		DCP_USE_DCACHE=1
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
		${PSA_CRYPTO_DRIVER_PATH}/osal/zephyr/
		${ZEPHYR_HAL_NXP_MODULE_DIR}/../../../zephyr/include/zephyr/arch/
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/osa/
		${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/components/osa/config
	)
	target_sources(
		McuxPsaCryptoDriverDcp
		PUBLIC
		${PSA_CRYPTO_DRIVER_PATH}/dcp/dcp.h
	)
	target_sources(
		McuxPsaCryptoDriverDcp
		PRIVATE
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
	)

	# fsl_dcp.c is conditionally compiled here only when the Zephyr MCUX DCP
	# crypto driver (CONFIG_CRYPTO_MCUX_DCP) is NOT enabled. When that driver is
	# active, hal_nxp already compiles fsl_dcp.c into libmodules__hal_nxp.a and
	# adding it here again causes duplicate symbol link errors.
	# When CONFIG_CRYPTO_MCUX_DCP is not set (e.g. tests/crypto/mbedtls_psa),
	# hal_nxp does not provide fsl_dcp.c, so we must compile it here.
	if(NOT CONFIG_CRYPTO_MCUX_DCP)
		target_sources(
			McuxPsaCryptoDriverDcp
			PRIVATE
			${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk-ng/drivers/dcp/fsl_dcp.c
		)
	endif()

	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/osal)

	# We must ensure we link this library into zephyr_interface
	target_link_libraries(McuxPsaCryptoDriverDcp PUBLIC zephyr_interface)


endif() # CONFIG_PSA_CRYPTO_DRIVER_DCP #

if(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC)
	message ("psa-crypto-driver-els module is included.")

if( CONFIG_BUILD_WITH_TFM)
	include(${CMAKE_CURRENT_LIST_DIR}/cmake/tfm.cmake)
else()
	zephyr_library_named(McuxPsaCryptoDriverElsPkc)
	set(NXP_MODULE_CRYPTO_PATH ${ZEPHYR_MBEDTLS_MODULE_DIR}/../)
	set(NXP_MODULE_ELS_PKC_PATH ${ZEPHYR_ELS_PKC_MODULE_DIR})
	
	zephyr_compile_definitions(
		# MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED
		PSA_CRYPTO_DRIVER_ELS_PKC
		PSA_CRYPTO_DRIVER_THREAD_EN
	)
endif()

	if (CONFIG_MCUX_PSA_CRYPTO_DRIVER_USE_ELS_PKC_SHA1)
		target_compile_definitions(
			McuxPsaCryptoDriverElsPkc
			PRIVATE
			MCUX_PSA_CRYPTO_DRIVER_USE_ELS_PKC_SHA1
		)
	endif()

	target_compile_definitions(
		McuxPsaCryptoDriverElsPkc
		PRIVATE
		MBEDTLS_MCUX_ENTROPY
	)

	target_include_directories(McuxPsaCryptoDriverElsPkc
		PUBLIC
		#psa-crypto-driver for els_pkc include paths
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/.
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/include/common
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/include/opaque
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/include/transparent
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/oracle
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/oracle/inc
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/oracle/platforms/rw61x
		${CMAKE_CURRENT_LIST_DIR}/osal
		${CMAKE_CURRENT_LIST_DIR}/osal/zephyr
		#include the psa-driver inlcude path from clib
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/inc
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/inc/internal
		#include McuxElsPkc include directories
		"$<TARGET_PROPERTY:McuxElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
	)

if(NOT CONFIG_BUILD_WITH_TFM)
	target_include_directories(McuxPsaCryptoDriverElsPkc
		PRIVATE
		# psa/crypto.h and psa/crypto_types.h
		${NXP_MODULE_CRYPTO_PATH}/mbedtls/include
		${NXP_MODULE_CRYPTO_PATH}/mbedtls/include/psa
		# for psa driver wrapper
		${NXP_MODULE_CRYPTO_PATH}/mbedtls/library
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/core
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/builtin/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/drivers/pqcp/src
		${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/dispatch
		# cmsis required to build els_pkc
		${NXP_MODULE_ELS_PKC_PATH}/src/platforms/rw61x/cmsis_cortex_m_5_5_1/inc
	)
endif()

	target_sources(
		McuxPsaCryptoDriverElsPkc
		PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/oracle/src/mcuxClPsaDriver_Oracle.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/oracle/src/mcuxClPsaDriver_Oracle_ElsUtils.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/oracle/src/mcuxClPsaDriver_Oracle_Utils.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/common/mcux_psa_els_pkc_common_init.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/common/mcux_psa_els_pkc_entropy.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/opaque/mcux_psa_els_pkc_opaque_aead.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/opaque/mcux_psa_els_pkc_opaque_asymmetric_signature.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/opaque/mcux_psa_els_pkc_opaque_cipher.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/opaque/mcux_psa_els_pkc_opaque_init.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/opaque/mcux_psa_els_pkc_opaque_key_generation.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/opaque/mcux_psa_els_pkc_opaque_mac.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_aead.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_asymmetric_signature.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_cipher.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_hash.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_init.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_key_generation.c
		${CMAKE_CURRENT_LIST_DIR}/els_pkc/src/transparent/mcux_psa_els_pkc_mac.c

		# add psa-driver source files from els_pkc(clib) in this (psa_crypto_driver)lib
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Aead.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Cipher.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_DER_functions.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Hash.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Key.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Mac.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Rsa.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Sign.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_UpdateKeyStatus.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Verify.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_export_public_key.c
		${NXP_MODULE_ELS_PKC_PATH}/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_generate_ecp_key.c
	)

	#link McuxElsPkc lib as psa-crypto-driver functions eventually calls els_pkc functions.
	target_link_libraries(McuxPsaCryptoDriverElsPkc PUBLIC McuxElsPkc)
if( NOT CONFIG_BUILD_WITH_TFM)
	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/osal)
	target_link_libraries(McuxPsaCryptoDriverElsPkc PUBLIC zephyr_interface)
endif()

endif() # CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC #
