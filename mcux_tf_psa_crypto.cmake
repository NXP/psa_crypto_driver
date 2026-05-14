#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

# TF-PSA-Crypto Core #
if(CONFIG_MCUX_COMPONENT_middleware.mbedtls.tf_psa_crypto)
    mcux_add_source(
        SOURCES # Sources
                core/alignment.h
                core/check_crypto_config.h
                core/psa_crypto.c
                core/psa_crypto_client.c
                core/psa_crypto_core.h
                core/psa_crypto_core_common.h
                core/psa_crypto_invasive.h
                core/psa_crypto_its.h
                core/psa_crypto_random.c
                core/psa_crypto_random.h
                core/psa_crypto_random_impl.h
                core/psa_crypto_slot_management.c
                core/psa_crypto_slot_management.h
                core/psa_crypto_storage.c
                core/psa_crypto_storage.h
                core/psa_its_file.c
                core/psa_util.c
                core/tf_psa_crypto_check_config.h
                core/tf_psa_crypto_common.h
                core/tf_psa_crypto_config.c
                core/tf_psa_crypto_platform_requirements.h
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
                include/tf-psa-crypto/private/crypto_adjust_config_auto_enabled.h
                include/tf-psa-crypto/private/crypto_adjust_config_dependencies.h
                include/tf-psa-crypto/private/crypto_adjust_config_derived.h
                include/tf-psa-crypto/private/crypto_adjust_config_key_pair_types.h
                include/tf-psa-crypto/private/crypto_adjust_config_support.h
                include/tf-psa-crypto/private/crypto_adjust_config_synonyms.h
                include/tf-psa-crypto/version.h
                # Extras (pk stack, lms, md, nist_kw - moved from builtin/src in 1.1.0)
                extras/lmots.c
                extras/lmots.h
                extras/lms.c
                extras/md.c
                extras/md_wrap.h
                extras/nist_kw.c
                extras/pk.c
                extras/pk_ecc.c
                extras/pk_internal.h
                extras/pk_rsa.c
                extras/pk_wrap.c
                extras/pk_wrap.h
                extras/pkparse.c
                extras/pkwrite.c
                extras/pkwrite.h
                # Utilities (asn1, base64, constant_time, oid, pem, pkcs5 - moved from builtin/src in 1.1.0)
                utilities/asn1parse.c
                utilities/asn1write.c
                utilities/base64.c
                utilities/base64_internal.h
                utilities/constant_time.c
                utilities/constant_time_impl.h
                utilities/constant_time_internal.h
                utilities/crypto_oid.h
                utilities/oid.c
                utilities/pem.c
                utilities/pkcs5.c
                # Dispatch (driver wrappers header - new location in 1.1.0)
                dispatch/psa_crypto_driver_wrappers_no_static.h
                # Platform (threading, platform, memory_buffer_alloc - moved from builtin/src in 1.1.0)
                platform/memory_buffer_alloc.c
                platform/platform.c
                platform/platform_util.c
                platform/threading.c
                platform/threading_internal.h
        BASE_PATH ${SdkRootDirPath}/middleware/mbedtls/tf-psa-crypto
    )
    mcux_add_include(
        INCLUDES core
                 dispatch
                 extras
                 include
                 include/mbedtls
                 include/mbedtls/private
                 include/psa
                 include/tf-psa-crypto
                 include/tf-psa-crypto/private
                 platform
                 utilities
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
                src/chacha20_neon.c
                src/chacha20_neon.h
                src/chachapoly.c
                src/cipher.c
                src/cipher_invasive.h
                src/cipher_wrap.c
                src/cipher_wrap.h
                src/cmac.c
                src/ctr.h
                src/ctr_drbg.c
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
                src/md5.c
                src/md_psa.h
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
                src/psa_crypto_xof.c
                src/psa_crypto_xof.h
                src/psa_util_internal.c
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
                # Include
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
                include/mbedtls/private/config_adjust_test_accelerators.h
                include/mbedtls/private/crypto_adjust_config_enable_builtins.h
                include/mbedtls/private/crypto_adjust_config_tweak_builtins.h
                include/mbedtls/private/crypto_builtin_composites.h
                include/mbedtls/private/crypto_builtin_key_derivation.h
                include/mbedtls/private/crypto_builtin_primitives.h
                include/mbedtls/private/ctr_drbg.h
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
