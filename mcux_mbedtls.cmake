#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

if(CONFIG_MCUX_COMPONENT_middleware.mbedtls)
    mcux_add_iar_configuration(
        CC  "--diag_suppress=Pa167,Pe177,Pe191,Pe546,Pe1215"
        CX  "--diag_suppress=Pa167,Pe177,Pe191,Pe546,Pe1215"
    )
    mcux_add_armgcc_configuration(
        CC  "-fomit-frame-pointer -Wno-unused-function"
    )
    mcux_add_source(
        SOURCES # Sources
                library/debug.c
                library/debug_internal.h
                library/mbedtls_check_config.h
                library/mbedtls_common.h
                library/mbedtls_config.c
                library/mbedtls_platform_requirements.h
                library/mbedtls_utils.h
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
                ssl_debug_helpers_generated.c
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
