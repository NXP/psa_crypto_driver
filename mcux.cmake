#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

########################
#         OSAL         #
########################

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.osal)
    mcux_add_source(
        SOURCES osal/osal_mutex.h
                osal/threading_alt.h
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
                osal/frtos/threading_alt.c
                osal/frtos/threading_alt_platform.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES osal/frtos
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.osal.zephyr)
    mcux_add_source(
        SOURCES osal/zephyr/osal_mutex.c
                osal/zephyr/osal_mutex_platform.h
                osal/zephyr/threading_alt.c
                osal/zephyr/threading_alt_platform.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES osal/zephyr
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.osal.baremetal)
    mcux_add_source(
        SOURCES osal/baremetal/osal_mutex.c
                osal/baremetal/osal_mutex_platform.h
                osal/baremetal/threading_alt.c
                osal/baremetal/threading_alt_platform.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES osal/baremetal
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

########################
#      Threading       #
########################

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.mbedtls_thread_alt)
    mcux_add_macro(
        "-DPSA_CRYPTO_DRIVER_THREAD_EN"
    )
endif()

#########################
# PSA Crypto HW Drivers #
#########################


####### ELS_PKC ########

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
        "-DPSA_CRYPTO_DRIVER_ELS_PKC"
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

####### DCP ########

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
        "-DPSA_CRYPTO_DRIVER_DCP"
    )
endif()

####### ELE S400 ########

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
        "-DPSA_ELE_S4XX_SD_NVM_MANAGER=1"
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
        "-DPSA_CRYPTO_DRIVER_ELE_S4XX"
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_psa_with_persistent_storage)
    mcux_add_macro(
        "-DPSA_CRYPTO_DRIVER_ELE_S4XX"
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

####### ELE S200 ########

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
        "-DPSA_CRYPTO_DRIVER_ELE_S2XX"
    )
endif()

####### CASPER ########

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
        "-DPSA_CRYPTO_DRIVER_CASPER"
    )
endif()

####### HASHCRYPT ########

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
        "-DPSA_CRYPTO_DRIVER_HASHCRYPT"
    )
endif()

####### CAAM ########

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
        "-DPSA_CRYPTO_DRIVER_CAAM"
    )

endif()

####### ELA CSEC ########

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
        "-DPSA_CRYPTO_DRIVER_ELA_CSEC"
    )

endif()

####### ELE HSEB ########

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
        "-DPSA_CRYPTO_DRIVER_ELE_HSEB"
    )
endif()

####### SGI ########

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
  mcux_add_macro("-DPSA_CRYPTO_DRIVER_SGI")
endif()

####### PKC ########

if(CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.pkc)
  mcux_add_source(SOURCES
    pkc/include/mcux_psa_pkc_asymmetric_signature.h
    pkc/include/mcux_psa_pkc_init.h
    pkc/include/mcux_psa_pkc_utils.h
    pkc/include/mcux_psa_pkc_key_generation.h
    pkc/src/mcux_psa_pkc_asymmetric_signature.c
    pkc/src/mcux_psa_pkc_init.c
    pkc/src/mcux_psa_pkc_utils.c
    pkc/src/mcux_psa_pkc_key_generation.c
	pkc/pkc.h
    BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/)
  mcux_add_include(
        INCLUDES pkc
                 pkc/include
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_macro(
        "PSA_CRYPTO_DRIVER_PKC"
    )
endif()

########################
#         TRNG         #
########################

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.use_trng_compile_option)
    # adding specific compile option to use HW TRNG
    mcux_add_macro(
        "-DMBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED"
    )
endif()

########################
#  EL2Go key recipes   #
########################

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

########################
#      Utilities       #
########################

if(CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.util.wrapcheck_static_inline)
  mcux_add_source(
    SOURCES utils/mcux_psa_util_wrapcheck_static_inline.h
    BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/)
  mcux_add_include(
    INCLUDES utils/
    BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/)
endif()

########################
#      MbedTLS         #
########################

if(CONFIG_MCUX_COMPONENT_middleware.mbedtls)
    mcux_add_iar_configuration(
        CC  "--diag_suppress=Pa167,Pe177,Pe191,Pe546"
        CX  "--diag_suppress=Pa167,Pe177,Pe191,Pe546"
    )
    mcux_add_armgcc_configuration(
        CC  "-fomit-frame-pointer -Wno-unused-function"
    )
    mcux_add_source(
        SOURCES # Sources
                library/debug.c
                library/debug_internal.h
                library/mbedtls_check_config.h
                library/mbedtls_config.c
                library/mps_common.h
                library/mps_error.h
                library/mps_reader.c
                library/mps_reader.h
                library/mps_trace.c
                library/mps_trace.h
                library/net_sockets.c
                library/pkcs7.c
                library/ssl_cache.c
                library/ssl_ciphersuites.c
                library/ssl_ciphersuites_internal.h
                library/ssl_client.c
                library/ssl_client.h
                library/ssl_cookie.c
                library/ssl_debug_helpers.h
                library/ssl_misc.h
                library/ssl_msg.c
                library/ssl_ticket.c
                library/ssl_tls.c
                library/ssl_tls12_client.c
                library/ssl_tls12_server.c
                library/ssl_tls13_client.c
                library/ssl_tls13_generic.c
                library/ssl_tls13_invasive.h
                library/ssl_tls13_keys.c
                library/ssl_tls13_keys.h
                library/ssl_tls13_server.c
                library/timing.c
                library/version.c
                library/x509.c
                library/x509_create.c
                library/x509_crl.c
                library/x509_crt.c
                library/x509_csr.c
                library/x509_internal.h
                library/x509_oid.c
                library/x509_oid.h
                library/x509write.c
                library/x509write_crt.c
                library/x509write_csr.c
                # Include
                include/mbedtls/build_info.h
                include/mbedtls/debug.h
                include/mbedtls/error.h
                include/mbedtls/mbedtls_config.h
                include/mbedtls/net_sockets.h
                include/mbedtls/oid.h
                include/mbedtls/pkcs7.h
                include/mbedtls/ssl.h
                include/mbedtls/ssl_cache.h
                include/mbedtls/ssl_ciphersuites.h
                include/mbedtls/ssl_cookie.h
                include/mbedtls/ssl_ticket.h
                include/mbedtls/timing.h
                include/mbedtls/version.h
                include/mbedtls/x509.h
                include/mbedtls/x509_crl.h
                include/mbedtls/x509_crt.h
                include/mbedtls/x509_csr.h
                include/mbedtls/private/config_adjust_x509.h
                include/mbedtls/private/config_adjust_ssl.h
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/
    )
    mcux_add_include(
        INCLUDES include
                 include/mbedtls
                 include/mbedtls/private
                 library
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/
    )

    # Generated files
    mcux_add_source(
        SOURCES # Sources
                mbedtls_config_check_user.h
                mbedtls_config_check_final.h
                mbedtls_config_check_before.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/generated_files_mbedtls
    )

    mcux_add_include(
        INCLUDES generated_files_mbedtls
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver
    )

endif()

########################
#    TF-PSA-Crypto     #
########################

# TF-PSA-Crypto Core #
if(CONFIG_MCUX_COMPONENT_middleware.mbedtls.tf_psa_crypto)
    mcux_add_source(
        SOURCES # Sources
                core/alignment.h
                core/psa_crypto.c
                core/psa_crypto_client.c
                core/psa_crypto_core.h
                core/psa_crypto_core_common.h
                # core/psa_crypto_driver_wrappers_no_static.h
                core/psa_crypto_invasive.h
                core/psa_crypto_its.h
                core/psa_crypto_random_impl.h
                core/psa_crypto_slot_management.c
                core/psa_crypto_slot_management.h
                core/psa_crypto_storage.c
                core/psa_crypto_storage.h
                core/psa_its_file.c
                core/tf_psa_crypto_check_config.h
                core/tf_psa_crypto_common.h
                core/tf_psa_crypto_config.c
                core/tf_psa_crypto_version.c
                # Include mbedtls
                include/mbedtls/asn1.h
                include/mbedtls/asn1write.h
                include/mbedtls/base64.h
                include/mbedtls/compat-3-crypto.h
                include/mbedtls/constant_time.h
                include/mbedtls/lms.h
                include/mbedtls/md.h
                include/mbedtls/memory_buffer_alloc.h
                include/mbedtls/nist_kw.h
                include/mbedtls/pem.h
                include/mbedtls/pk.h
                include/mbedtls/platform.h
                include/mbedtls/platform_time.h
                include/mbedtls/platform_util.h
                include/mbedtls/psa_util.h
                include/mbedtls/threading.h
                include/mbedtls/private/pk_private.h
                # Include psa
                include/psa/crypto.h
                include/psa/crypto_adjust_auto_enabled.h
                include/psa/crypto_adjust_config_dependencies.h
                include/psa/crypto_adjust_config_derived.h
                include/psa/crypto_adjust_config_key_pair_types.h
                include/psa/crypto_adjust_config_synonyms.h
                include/psa/crypto_builtin_composites.h
                include/psa/crypto_builtin_key_derivation.h
                include/psa/crypto_builtin_primitives.h
                include/psa/crypto_compat.h
                include/psa/crypto_config.h
                include/psa/crypto_driver_common.h
                include/psa/crypto_driver_contexts_composites.h
                include/psa/crypto_driver_contexts_key_derivation.h
                include/psa/crypto_driver_contexts_primitives.h
                include/psa/crypto_driver_random.h
                include/psa/crypto_extra.h
                include/psa/crypto_platform.h
                include/psa/crypto_sizes.h
                include/psa/crypto_struct.h
                include/psa/crypto_types.h
                include/psa/crypto_values.h
                # Include tf-psa-crypto
                include/tf-psa-crypto/build_info.h
                include/tf-psa-crypto/version.h
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/tf-psa-crypto
    )
    mcux_add_include(
        INCLUDES core 
                 include
                 include/mbedtls
                 include/mbedtls/private
                 include/psa
                 include/tf-psa-crypto
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/tf-psa-crypto
    )

    # Generated files
    mcux_add_source(
        SOURCES # Sources
                tf_psa_crypto_config_check_user.h
                tf_psa_crypto_config_check_final.h
                tf_psa_crypto_config_check_before.h
                psa_crypto_driver_wrappers_no_static.c
                psa_crypto_driver_wrappers.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/generated_files_tf_psa_crypto
    )

    mcux_add_include(
        INCLUDES generated_files_tf_psa_crypto
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver
    )

    # MCUX defines for key location propagation
    mcux_add_source(
        SOURCES # Sources
                mcux_psa_defines.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver
    )
    mcux_add_include(
        INCLUDES .
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver
    )


endif()

# TF-PSA-Crypto Builtin driver #
if(CONFIG_MCUX_COMPONENT_middleware.mbedtls.tf_psa_crypto.builtin_driver)
    mcux_add_source(
        SOURCES # Sources
                src/aes.c
                src/aesce.c
                src/aesce.h
                src/aesni.c
                src/aesni.h
                src/aria.c
                src/asn1parse.c
                src/asn1write.c
                src/base64.c
                src/base64_internal.h
                src/bignum.c
                src/bignum_core.c
                src/bignum_core.h
                src/bignum_core_invasive.h
                src/bignum_internal.h
                src/bignum_mod.c
                src/bignum_mod.h
                src/bignum_mod_raw.c
                src/bignum_mod_raw.h
                src/bignum_mod_raw_invasive.h
                src/block_cipher.c
                src/block_cipher_internal.h
                src/bn_mul.h
                src/camellia.c
                src/ccm.c
                src/chacha20.c
                src/chachapoly.c
                src/check_crypto_config.h
                src/cipher.c
                src/cipher_invasive.h
                src/cipher_wrap.c
                src/cipher_wrap.h
                src/cmac.c
                src/constant_time.c
                src/constant_time_impl.h
                src/constant_time_internal.h
                src/crypto_oid.h
                src/ctr.h
                src/ctr_drbg.c
                src/ecdh.c
                src/ecdsa.c
                src/ecjpake.c
                src/ecp.c
                src/ecp_curves.c
                src/ecp_curves_new.c
                src/ecp_invasive.h
                src/entropy.c
                src/entropy_poll.c
                src/entropy_poll.h
                src/gcm.c
                src/hmac_drbg.c
                src/lmots.c
                src/lmots.h
                src/lms.c
                src/md.c
                src/md5.c
                src/md_psa.h
                src/md_wrap.h
                src/memory_buffer_alloc.c
                src/nist_kw.c
                src/oid.c
                src/pem.c
                src/pk.c
                src/pk_ecc.c
                src/pk_internal.h
                src/pk_rsa.c
                src/pk_wrap.c
                src/pk_wrap.h
                src/pkcs5.c
                src/pkparse.c
                src/pkwrite.c
                src/pkwrite.h
                src/platform.c
                src/platform_util.c
                src/poly1305.c
                src/psa_crypto_aead.c
                src/psa_crypto_aead.h
                src/psa_crypto_cipher.c
                src/psa_crypto_cipher.h
                src/psa_crypto_ecp.c
                src/psa_crypto_ecp.h
                src/psa_crypto_ffdh.c
                src/psa_crypto_ffdh.h
                src/psa_crypto_hash.c
                src/psa_crypto_hash.h
                src/psa_crypto_mac.c
                src/psa_crypto_mac.h
                src/psa_crypto_pake.c
                src/psa_crypto_pake.h
                src/psa_crypto_rsa.c
                src/psa_crypto_rsa.h
                src/psa_util.c
                src/psa_util_internal.h
                src/ripemd160.c
                src/rsa.c
                src/rsa_alt_helpers.c
                src/rsa_alt_helpers.h
                src/rsa_internal.h
                src/sha1.c
                src/sha256.c
                src/sha3.c
                src/sha512.c
                src/threading.c
                src/threading_internal.h
                # Include
                include/mbedtls/config_adjust_legacy_crypto.h
                include/mbedtls/private_access.h
                include/mbedtls/private/aes.h
                include/mbedtls/private/aria.h
                include/mbedtls/private/bignum.h
                include/mbedtls/private/block_cipher.h
                include/mbedtls/private/camellia.h
                include/mbedtls/private/ccm.h
                include/mbedtls/private/chacha20.h
                include/mbedtls/private/chachapoly.h
                include/mbedtls/private/cipher.h
                include/mbedtls/private/cmac.h
                include/mbedtls/private/config_adjust_legacy_from_psa.h
                include/mbedtls/private/config_adjust_test_accelerators.h
                include/mbedtls/private/config_psa.h
                include/mbedtls/private/ctr_drbg.h
                include/mbedtls/private/ecdh.h
                include/mbedtls/private/ecdsa.h
                include/mbedtls/private/ecjpake.h
                include/mbedtls/private/ecp.h
                include/mbedtls/private/entropy.h
                include/mbedtls/private/error_common.h
                include/mbedtls/private/gcm.h
                include/mbedtls/private/hmac_drbg.h
                include/mbedtls/private/md5.h
                include/mbedtls/private/pkcs5.h
                include/mbedtls/private/poly1305.h
                include/mbedtls/private/ripemd160.h
                include/mbedtls/private/rsa.h
                include/mbedtls/private/sha1.h
                include/mbedtls/private/sha256.h
                include/mbedtls/private/sha3.h
                include/mbedtls/private/sha512.h
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/tf-psa-crypto/drivers/builtin
    )
    mcux_add_include(
        INCLUDES src
                 include
                 include/mbedtls
                 include/mbedtls/private
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/tf-psa-crypto/drivers/builtin
    )
endif()

# MbedTLS default config file #
if(CONFIG_MCUX_COMPONENT_middleware.mbedtls.default_config)
    mcux_add_macro(
        "-DMBEDTLS_CONFIG_FILE=\\\"mcux_mbedtls_config.h\\\""
    )

    mcux_add_source(
        SOURCES configs/mcux_mbedtls_config.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES configs
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()

# TF-PSA-Crypto default config file #
if(CONFIG_MCUX_COMPONENT_middleware.mbedtls.tf_psa_crypto.default_config)
    mcux_add_macro(
        "-DTF_PSA_CRYPTO_CONFIG_FILE=\\\"mcux_crypto_config.h\\\""
    )

    mcux_add_source(
        SOURCES configs/mcux_crypto_config.h
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES configs
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
endif()