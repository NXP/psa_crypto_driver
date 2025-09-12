#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.osal)
    mcux_add_source(
        SOURCES osal/osal_mutex.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES osal
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.osal.frtos)
    mcux_add_source(
        SOURCES osal/frtos/osal_mutex.c
                osal/frtos/osal_mutex_platform.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES osal/frtos
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.osal.baremetal)
    mcux_add_source(
        SOURCES osal/baremetal/osal_mutex.c
                osal/baremetal/osal_mutex_platform.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES osal/baremetal
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.mbedtls_thread_alt)
    mcux_add_source(
        SOURCES mbedtls_thread_alt/threading_alt.c
                mbedtls_thread_alt/threading_alt.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES mbedtls_thread_alt
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
         CC "-DPSA_CRYPTO_DRIVER_THREAD_EN"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.use_trng_compile_option)
    # adding specific compile option to use HW TRNG
    mcux_add_macro(
         CC "-DMBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED\
            "
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.oracle.rw61x)
    mcux_add_source(
        SOURCES els_pkc/oracle/platforms/rw61x/mcuxClPsaDriver_Oracle_KeyRecipes.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/oracle/platforms/rw61x
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.oracle.mcxn)
    mcux_add_source(
        SOURCES els_pkc/oracle/platforms/mcxn/mcuxClPsaDriver_Oracle_KeyRecipes.h
                els_pkc/oracle/platforms/mcxn/mcuxClPsaDriver_Oracle_KeyRecipes_Utils.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/oracle/platforms/mcxn
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.oracle.mimxrt)
    mcux_add_source(
        SOURCES els_pkc/oracle/platforms/mimxrt/mcuxClPsaDriver_Oracle_KeyRecipes.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/oracle/platforms/mimxrt
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.oracle.lpc)
    mcux_add_source(
        SOURCES els_pkc/oracle/platforms/lpc/mcuxClPsaDriver_Oracle_KeyRecipes.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/oracle/platforms/lpc
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.oracle)
    mcux_add_source(
        SOURCES els_pkc/oracle/inc/mcuxClPsaDriver_Oracle_Interface_builtin_key_ids.h
                els_pkc/oracle/inc/mcuxClPsaDriver_Oracle_Interface_key_locations.h
                els_pkc/oracle/inc/mcuxClPsaDriver_Oracle_ElsUtils.h
                els_pkc/oracle/inc/mcuxClPsaDriver_Oracle_Macros.h
                els_pkc/oracle/inc/mcuxClPsaDriver_Oracle_Utils.h
                els_pkc/oracle/src/mcuxClPsaDriver_Oracle.c
                els_pkc/oracle/src/mcuxClPsaDriver_Oracle_ElsUtils.c
                els_pkc/oracle/src/mcuxClPsaDriver_Oracle_Utils.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/oracle/inc
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.common)
    mcux_add_source(
        SOURCES els_pkc/include/common/mcux_psa_els_pkc_common_init.h
                els_pkc/include/common/mcux_psa_els_pkc_entropy.h
                els_pkc/src/common/mcux_psa_els_pkc_common_init.c
                els_pkc/src/common/mcux_psa_els_pkc_entropy.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/include/common
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.transparent)
    mcux_add_source(
        SOURCES els_pkc/include/transparent/mcux_psa_els_pkc_aead.h
                els_pkc/include/transparent/mcux_psa_els_pkc_asymmetric_signature.h
                els_pkc/include/transparent/mcux_psa_els_pkc_cipher.h
                els_pkc/include/transparent/mcux_psa_els_pkc_hash.h
                els_pkc/include/transparent/mcux_psa_els_pkc_init.h
                els_pkc/include/transparent/mcux_psa_els_pkc_key_generation.h
                els_pkc/include/transparent/mcux_psa_els_pkc_mac.h
                els_pkc/src/transparent/mcux_psa_els_pkc_aead.c
                els_pkc/src/transparent/mcux_psa_els_pkc_asymmetric_signature.c
                els_pkc/src/transparent/mcux_psa_els_pkc_cipher.c
                els_pkc/src/transparent/mcux_psa_els_pkc_hash.c
                els_pkc/src/transparent/mcux_psa_els_pkc_init.c
                els_pkc/src/transparent/mcux_psa_els_pkc_key_generation.c
                els_pkc/src/transparent/mcux_psa_els_pkc_mac.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/include/transparent
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc.opaque)
    mcux_add_source(
        SOURCES els_pkc/include/opaque/mcux_psa_els_pkc_opaque_aead.h
                els_pkc/include/opaque/mcux_psa_els_pkc_opaque_asymmetric_signature.h
                els_pkc/include/opaque/mcux_psa_els_pkc_opaque_cipher.h
                els_pkc/include/opaque/mcux_psa_els_pkc_opaque_init.h
                els_pkc/include/opaque/mcux_psa_els_pkc_opaque_key_generation.h
                els_pkc/include/opaque/mcux_psa_els_pkc_opaque_mac.h
                els_pkc/src/opaque/mcux_psa_els_pkc_opaque_aead.c
                els_pkc/src/opaque/mcux_psa_els_pkc_opaque_asymmetric_signature.c
                els_pkc/src/opaque/mcux_psa_els_pkc_opaque_cipher.c
                els_pkc/src/opaque/mcux_psa_els_pkc_opaque_init.c
                els_pkc/src/opaque/mcux_psa_els_pkc_opaque_key_generation.c
                els_pkc/src/opaque/mcux_psa_els_pkc_opaque_mac.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc/include/opaque
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.els_pkc)
    mcux_add_macro(
         CC "-DPSA_CRYPTO_DRIVER_ELS_PKC\
            "
    )
    mcux_add_source(
        SOURCES els_pkc/els_pkc_driver.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES els_pkc
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.dcp)
    mcux_add_source(
        SOURCES dcp/dcp.h
                dcp/dcp_crypto_primitives.h
                dcp/include/mcux_psa_dcp_cipher.h
                dcp/include/mcux_psa_dcp_common_init.h
                dcp/include/mcux_psa_dcp_entropy.h
                dcp/include/mcux_psa_dcp_hash.h
                dcp/include/mcux_psa_dcp_init.h
                dcp/src/mcux_psa_dcp_cipher.c
                dcp/src/mcux_psa_dcp_common_init.c
                dcp/src/mcux_psa_dcp_entropy.c
                dcp/src/mcux_psa_dcp_hash.c
                dcp/src/mcux_psa_dcp_init.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES dcp
                 dcp/include
                 dcp/common/include
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_DCP"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_rng)
    mcux_add_source(
        SOURCES ele_s4xx/ele_s4xx.h
                ele_s4xx/ele_fw.h
                ele_s4xx/src/common/mcux_psa_s4xx_common_init.c
                ele_s4xx/include/common/mcux_psa_s4xx_common_init.h
                ele_s4xx/src/common/mcux_psa_s4xx_entropy.c
                ele_s4xx/include/common/mcux_psa_s4xx_entropy.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s4xx
                 ele_s4xx/include
                 ele_s4xx/include/common
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_psa_transparent)
    mcux_add_source(
        SOURCES ele_s4xx/ele_s4xx_crypto_primitives.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_init.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_init.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_key_generation.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_key_generation.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_hash.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_hash.h
                ele_s4xx/src/common/mcux_psa_s4xx_common_key_management.c
                ele_s4xx/include/common/mcux_psa_s4xx_common_key_management.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_aead.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_aead.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_cipher.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_cipher.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_asymmetric_encryption.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_asymmetric_encryption.h
                ele_s4xx/src/transparent/mcux_psa_s4xx_asymmetric_signature.c
                ele_s4xx/include/transparent/mcux_psa_s4xx_asymmetric_signature.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s4xx/
                 ele_s4xx/include/common
                 ele_s4xx/include/transparent
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_sd_nvm_mgr)
    mcux_add_source(
        SOURCES ele_s4xx/src/common/mcux_psa_s4xx_sdmmc_nvm_manager.c
                ele_s4xx/include/common/mcux_psa_s4xx_sdmmc_nvm_manager.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s4xx/include/common
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        CC "-DPSA_ELE_S4XX_SD_NVM_MANAGER=1\
           "
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_psa_opaque)
    mcux_add_source(
        SOURCES ele_s4xx/ele_s4xx_crypto_primitives.h
                ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_init.c
                ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_init.h
                ele_s4xx/src/common/mcux_psa_s4xx_common_key_management.c
                ele_s4xx/include/common/mcux_psa_s4xx_common_key_management.h
                ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_key_generation.c
                ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_key_generation.h
                ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_asymmetric_signature.c
                ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_asymmetric_signature.h
                ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_cipher.c
                ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_cipher.h
                ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_aead.c
                ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_aead.h
                ele_s4xx/src/opaque/mcux_psa_s4xx_opaque_mac.c
                ele_s4xx/include/opaque/mcux_psa_s4xx_opaque_mac.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s4xx/
                 ele_s4xx/include/common
                 ele_s4xx/include/opaque
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_psa)
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_ELE_S4XX"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_psa_with_persistent_storage)
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_ELE_S4XX"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s200.common)
    mcux_add_source(
        SOURCES ele_s200/include/common/mcux_psa_s2xx_common_init.h
                ele_s200/include/common/mcux_psa_s2xx_entropy.h
                ele_s200/include/common/mcux_psa_s2xx_common_key_management.h
                ele_s200/include/common/mcux_psa_s2xx_key_locations.h
                ele_s200/include/common/mcux_psa_s2xx_common_compute.h
                ele_s200/src/common/mcux_psa_s2xx_common_init.c
                ele_s200/src/common/mcux_psa_s2xx_entropy.c
                ele_s200/src/common/mcux_psa_s2xx_common_key_management.c
                ele_s200/src/common/mcux_psa_s2xx_common_compute.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s200/include/common
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s200.transparent)
    mcux_add_source(
        SOURCES ele_s200/include/transparent/mcux_psa_s2xx_aead.h
                ele_s200/include/transparent/mcux_psa_s2xx_cipher.h
                ele_s200/include/transparent/mcux_psa_s2xx_hash.h
                ele_s200/include/transparent/mcux_psa_s2xx_init.h
                ele_s200/include/transparent/mcux_psa_s2xx_mac.h
                ele_s200/include/transparent/mcux_psa_s2xx_asymmetric_signature.h
                ele_s200/include/transparent/mcux_psa_s2xx_key_generation.h
                ele_s200/src/transparent/mcux_psa_s2xx_aead.c
                ele_s200/src/transparent/mcux_psa_s2xx_cipher.c
                ele_s200/src/transparent/mcux_psa_s2xx_hash.c
                ele_s200/src/transparent/mcux_psa_s2xx_init.c
                ele_s200/src/transparent/mcux_psa_s2xx_mac.c
                ele_s200/src/transparent/mcux_psa_s2xx_asymmetric_signature.c
                ele_s200/src/transparent/mcux_psa_s2xx_key_generation.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s200/include/transparent
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s200.opaque)
    mcux_add_source(
        SOURCES ele_s200/include/opaque/mcux_psa_s2xx_opaque_key_generation.h
                ele_s200/include/opaque/mcux_psa_s2xx_opaque_cipher.h
                ele_s200/include/opaque/mcux_psa_s2xx_opaque_aead.h
                ele_s200/include/opaque/mcux_psa_s2xx_opaque_asymmetric_signature.h
                ele_s200/include/opaque/mcux_psa_s2xx_opaque_mac.h
                ele_s200/src/opaque/mcux_psa_s2xx_opaque_key_generation.c
                ele_s200/src/opaque/mcux_psa_s2xx_opaque_cipher.c
                ele_s200/src/opaque/mcux_psa_s2xx_opaque_aead.c
                ele_s200/src/opaque/mcux_psa_s2xx_opaque_asymmetric_signature.c
                ele_s200/src/opaque/mcux_psa_s2xx_opaque_mac.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s200/include/opaque
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s200)
    mcux_add_source(
        SOURCES ele_s200/ele_s2xx_crypto_primitives.h
                ele_s200/ele_s2xx.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s200
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_ELE_S2XX"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.casper)
    mcux_add_source(
        SOURCES casper/casper.h
                casper/common/include/mcux_psa_common_key_management.h
                casper/common/src/mcux_psa_common_key_management.c
                casper/include/mcux_psa_casper_common_asymmetric_signature.h
                casper/include/mcux_psa_casper_common_init.h
                casper/include/mcux_psa_casper_ecdsa_port.h
                casper/include/mcux_psa_casper_ecp_port.h
                casper/include/mcux_psa_casper_init.h
                casper/include/mcux_psa_casper_key_generation_port.h
                casper/src/mcux_psa_casper_common_asymmetric_signature.c
                casper/src/mcux_psa_casper_common_init.c
                casper/src/mcux_psa_casper_ecdsa_port.c
                casper/src/mcux_psa_casper_ecp_port.c
                casper/src/mcux_psa_casper_init.c
                casper/src/mcux_psa_casper_key_generation_port.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES casper
                 casper/include
                 casper/common/include
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        "PSA_CRYPTO_DRIVER_CASPER"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.hashcrypt)
    mcux_add_source(
        SOURCES hashcrypt/hashcrypt.h
                hashcrypt/hashcrypt_crypto_primitives.h
                hashcrypt/include/mcux_psa_hashcrypt_common_cipher.h
                hashcrypt/include/mcux_psa_hashcrypt_common_init.h
                hashcrypt/include/mcux_psa_hashcrypt_entropy.h
                hashcrypt/include/mcux_psa_hashcrypt_hash.h
                hashcrypt/include/mcux_psa_hashcrypt_init.h
                hashcrypt/src/mcux_psa_hashcrypt_common_cipher.c
                hashcrypt/src/mcux_psa_hashcrypt_common_init.c
                hashcrypt/src/mcux_psa_hashcrypt_entropy.c
                hashcrypt/src/mcux_psa_hashcrypt_hash.c
                hashcrypt/src/mcux_psa_hashcrypt_init.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES hashcrypt
                 hashcrypt/include
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        "PSA_CRYPTO_DRIVER_HASHCRYPT"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.caam)
    mcux_add_source(
        SOURCES caam/caam_crypto_primitives.h
                caam/caam.h
                caam/src/mcux_psa_caam_common_aead.c
                caam/src/mcux_psa_caam_common_asymmetric_encryption.c
                caam/src/mcux_psa_caam_common_asymmetric_signature.c
                caam/src/mcux_psa_caam_common_cipher.c
                caam/src/mcux_psa_caam_common_init.c
                caam/src/mcux_psa_caam_common_key_generation.c
                caam/src/mcux_psa_caam_common_mac.c
                caam/src/mcux_psa_caam_entropy.c
                caam/src/mcux_psa_caam_hash.c
                caam/src/mcux_psa_caam_init.c
                caam/src/mcux_psa_caam_utils.c
                caam/include/mcux_psa_caam_common_aead.h
                caam/include/mcux_psa_caam_common_asymmetric_encryption.h
                caam/include/mcux_psa_caam_common_asymmetric_signature.h
                caam/include/mcux_psa_caam_common_cipher.h
                caam/include/mcux_psa_caam_common_init.h
                caam/include/mcux_psa_caam_common_key_generation.h
                caam/include/mcux_psa_caam_common_mac.h
                caam/include/mcux_psa_caam_entropy.h
                caam/include/mcux_psa_caam_hash.h
                caam/include/mcux_psa_caam_init.h
                caam/include/mcux_psa_caam_utils.h
                caam/common/src/mcux_psa_common_key_management.c
                caam/common/src/mcux_psa_mbedtls_origin.c
                caam/common/include/mcux_psa_common_key_management.h
                caam/common/include/mcux_psa_mbedtls_origin.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES caam
        INCLUDES caam/include
        INCLUDES caam/common/include
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_CAAM"
    )

endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ela_csec)
    mcux_add_source(
        SOURCES ela_csec/ela_csec.h
                ela_csec/include/common/mcux_psa_ela_csec_common_init.h
                ela_csec/include/common/mcux_psa_ela_csec_entropy.h
                ela_csec/src/common/mcux_psa_ela_csec_common_init.c
                ela_csec/src/common/mcux_psa_ela_csec_entropy.c
                ela_csec/include/transparent/mcux_psa_ela_csec_cipher.h
                ela_csec/include/transparent/mcux_psa_ela_csec_init.h
                ela_csec/include/transparent/mcux_psa_ela_csec_mac.h
                ela_csec/src/transparent/mcux_psa_ela_csec_cipher.c
                ela_csec/src/transparent/mcux_psa_ela_csec_init.c
                ela_csec/src/transparent/mcux_psa_ela_csec_mac.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ela_csec
                 ela_csec/include/common
                 ela_csec/include/transparent
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_ELA_CSEC"
    )

endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_hseb)
    mcux_add_source(
        SOURCES ele_hseb/ele_hseb_readme.md
                ele_hseb/ele_hseb.h
                ele_hseb/ele_hseb_crypto_primitives.h
                ele_hseb/ele_hseb_crypto_composites.h
                ele_hseb/include/common/mcux_psa_ele_hseb_common_init.h
                ele_hseb/include/common/mcux_psa_ele_hseb_entropy.h
                ele_hseb/include/common/mcux_psa_ele_hseb_translate.h
                ele_hseb/include/common/mcux_psa_ele_hseb_key_management.h
                ele_hseb/include/common/mcux_psa_ele_hseb_utils.h
                ele_hseb/src/common/mcux_psa_ele_hseb_common_init.c
                ele_hseb/src/common/mcux_psa_ele_hseb_entropy.c
                ele_hseb/src/common/mcux_psa_ele_hseb_translate.c
                ele_hseb/src/common/mcux_psa_ele_hseb_key_management.c
                ele_hseb/src/common/mcux_psa_ele_hseb_utils.c
                ele_hseb/include/transparent/mcux_psa_ele_hseb_asymmetric_signature.h
                ele_hseb/include/transparent/mcux_psa_ele_hseb_cipher.h
                ele_hseb/include/transparent/mcux_psa_ele_hseb_hash.h
                ele_hseb/include/transparent/mcux_psa_ele_hseb_init.h
                ele_hseb/include/transparent/mcux_psa_ele_hseb_mac.h
                ele_hseb/src/transparent/mcux_psa_ele_hseb_asymmetric_signature.c
                ele_hseb/src/transparent/mcux_psa_ele_hseb_cipher.c
                ele_hseb/src/transparent/mcux_psa_ele_hseb_hash.c
                ele_hseb/src/transparent/mcux_psa_ele_hseb_init.c
                ele_hseb/src/transparent/mcux_psa_ele_hseb_mac.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_hseb
                 ele_hseb/include/common
                 ele_hseb/include/transparent
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        CC  "-DPSA_CRYPTO_DRIVER_ELE_HSEB"
    )
endif()

if(CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.sgi.common)
  mcux_add_source(
    SOURCES
    sgi/include/common/mcux_psa_sgi_common_init.h
    sgi/include/common/mcux_psa_sgi_entropy.h
    sgi/src/common/mcux_psa_sgi_common_init.c
    sgi/src/common/mcux_psa_sgi_entropy.c
    BASE_PATH
    ${SdkRootDirPath}/components/psa_crypto_driver/)
  mcux_add_include(INCLUDES sgi/include/common BASE_PATH
                   ${SdkRootDirPath}/components/psa_crypto_driver/)
endif()

if(CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.sgi.transparent)
  mcux_add_source(
    SOURCES
    sgi/include/transparent/mcux_psa_sgi_cipher.h
    sgi/include/transparent/mcux_psa_sgi_aead.h
    sgi/include/transparent/mcux_psa_sgi_hash.h
    sgi/include/transparent/mcux_psa_sgi_init.h
    sgi/include/transparent/mcux_psa_sgi_mac.h
    sgi/src/transparent/mcux_psa_sgi_aead.c
    sgi/src/transparent/mcux_psa_sgi_cipher.c
    sgi/src/transparent/mcux_psa_sgi_hash.c
    sgi/src/transparent/mcux_psa_sgi_init.c
    sgi/src/transparent/mcux_psa_sgi_mac.c
    BASE_PATH
    ${SdkRootDirPath}/components/psa_crypto_driver/)
  mcux_add_include(INCLUDES sgi/include/transparent BASE_PATH
                   ${SdkRootDirPath}/components/psa_crypto_driver/)
endif()

if(CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.sgi)
  mcux_add_source(SOURCES sgi/sgi_crypto_primitives.h sgi/sgi.h BASE_PATH
                  ${SdkRootDirPath}/components/psa_crypto_driver/)
  mcux_add_include(INCLUDES sgi BASE_PATH
                   ${SdkRootDirPath}/components/psa_crypto_driver/)
  mcux_add_macro(CC "-DPSA_CRYPTO_DRIVER_SGI")
  mcux_add_macro(CC "-DMBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED")
endif()