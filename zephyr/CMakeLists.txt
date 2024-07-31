#-------------------------------------------------------------------------------
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC AND NOT CONFIG_BUILD_WITH_TFM)
  message ("psa-crypto-driver module is included.")
  add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../ psa_crypto_driver)
  zephyr_include_directories("$<TARGET_PROPERTY:McuxPsaCryptoDriverElsPkc,INTERFACE_INCLUDE_DIRECTORIES>")
  target_link_libraries(app PUBLIC McuxPsaCryptoDriverElsPkc)
endif()
