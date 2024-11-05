#
# Copyright 2024 NXP
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
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s4xx_psa_with_persistent_storage)
endif()

if (CONFIG_MCUX_COMPONENT_component.psa_crypto_driver.ele_s200.common)
    mcux_add_source(
        SOURCES ele_s200/include/common/mcux_psa_s2xx_common_init.h
                ele_s200/include/common/mcux_psa_s2xx_entropy.h
                ele_s200/src/common/mcux_psa_s2xx_common_init.c
                ele_s200/src/common/mcux_psa_s2xx_entropy.c
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
                ele_s200/src/transparent/mcux_psa_s2xx_aead.c
                ele_s200/src/transparent/mcux_psa_s2xx_cipher.c
                ele_s200/src/transparent/mcux_psa_s2xx_hash.c
                ele_s200/src/transparent/mcux_psa_s2xx_init.c
                ele_s200/src/transparent/mcux_psa_s2xx_mac.c
        BASE_PATH ${SdkRootDirPath}/components/psa_crypto_driver/
    )
    mcux_add_include(
        INCLUDES ele_s200/include/transparent
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
endif()
