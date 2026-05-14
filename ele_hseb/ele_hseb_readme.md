# ELE HSEB Port for the PSA Crypto API

## Key Management and Key Catalogs

The ELE HSEB component utilizes key catalogs for setting up the internal
keystore. These catalogs may be customized to enable or disable support for
various key types and key sizes. Constraints on these key catalogs may
be found in the HSE API reference manual.

MbedTLS3.x / PSA examples provided in the SDK are using the default key
catalogs, which can be found in the underlying `ele_hseb` component.
By default, key catalog initialization based on the configurations provided as
part of `ele_hseb` is done during the first call to `psa_crypto_init()`.
Please refer to the [Additional optional features](#additional-optional-features)
section and the ELE HSEB component documentation for more details on manual
catalog initialization and configuration customization.

# Additional optional features
The ELE HSEB PSA driver supports the following optional features
that can be configured with their respective Kconfig options:

* `MCUX_COMPONENT_component.psa_crypto_driver.ele_hseb.feature.autoformat_key_catalogs`

  *Enabled by default*. When disabled, this option removes automatic key catalog
  formatting during `psa_crypto_init()`. Users must manually format their key
  catalogs by calling `FormatKeyCatalogs()` and `HKF_Init()` before using PSA
  crypto operations.

  **NOTE**: If users pre-format their key catalogs when this option is enabled,
  the `psa_crypto_init()` function will reformat the key catalogs, removing all
  any previously stored keys.

* `MCUX_COMPONENT_component.psa_crypto_driver.ele_hseb.feature.use_custom_config_header`

  *Disabled by default*. When enabled, this option allows users to provide
  custom key catalog configurations tailored to their specific application use-
  cases. The provided PSA feature set may not be fully supported with
  custom configurations. Please refer to the default configuration for reference
  on how to configure your device.
  The custom configuration header file name is to be configured via the
  `CONFIG_ELE_HSEB_CUSTOM_CONFIG_HEADER` symbol and **MUST** be a quoted string.
  The provided custom Key Catalog initializer lists **MUST** be named
  `HSE_NVM_KEY_CATALOG_CFG` and `HSE_RAM_KEY_CATALOG_CFG`.
  The header file **SHOULD** be placed in the application's include path and
  will be automatically included by the ELE HSEB PSA driver during compilation.
  Otherwise the application include paths need to be updated by the user.

# Hardware Limitations

The ELE HSEB PSA driver implementation is subject to the following hardware
limitations.

* For PSA_KEY_TYPE_HMAC, the only supported key bit sizes are in the range
  [128, 1024].

# Supported Algorithms
Below is a list of algorithms supported by the current version of the ELE HSEB
port. Key types and sizes are also specified where relevant.

* Transparent
    * Cipher
        * One-Go
            * PSA_ALG_ECB_NO_PADDING
            * PSA_ALG_CBC_NO_PADDING
            * PSA_ALG_CTR
            * PSA_ALG_CFB
            * PSA_ALG_OFB
        * Multipart
            * PSA_ALG_ECB_NO_PADDING
            * PSA_ALG_CBC_NO_PADDING
            * PSA_ALG_CTR
            * PSA_ALG_CFB
            * PSA_ALG_OFB
    * Hash
        * One-Go
            * PSA_ALG_SHA_1
            * PSA_ALG_SHA_224
            * PSA_ALG_SHA_256
            * PSA_ALG_SHA_384
            * PSA_ALG_SHA_512
            * PSA_ALG_SHA_512_224
            * PSA_ALG_SHA_512_256
            * PSA_ALG_SHA3_224
            * PSA_ALG_SHA3_256
            * PSA_ALG_SHA3_384
            * PSA_ALG_SHA3_512
        * Multipart
            * PSA_ALG_SHA_1
            * PSA_ALG_SHA_224
            * PSA_ALG_SHA_256
            * PSA_ALG_SHA_384
            * PSA_ALG_SHA_512
            * PSA_ALG_SHA_512_224
            * PSA_ALG_SHA_512_256
            * PSA_ALG_SHA3_224
            * PSA_ALG_SHA3_256
            * PSA_ALG_SHA3_384
            * PSA_ALG_SHA3_512
    * MAC
        * One-Go
            * PSA_ALG_CMAC
            * PSA_ALG_HMAC(PSA_ALG_SHA_1)
            * PSA_ALG_HMAC(PSA_ALG_SHA_224)
            * PSA_ALG_HMAC(PSA_ALG_SHA_256)
            * PSA_ALG_HMAC(PSA_ALG_SHA_384)
            * PSA_ALG_HMAC(PSA_ALG_SHA_512)
            * PSA_ALG_HMAC(PSA_ALG_SHA_512_224)
            * PSA_ALG_HMAC(PSA_ALG_SHA_512_256)
        * Multipart
            * PSA_ALG_CMAC
            * PSA_ALG_HMAC(PSA_ALG_SHA_1)
            * PSA_ALG_HMAC(PSA_ALG_SHA_224)
            * PSA_ALG_HMAC(PSA_ALG_SHA_256)
            * PSA_ALG_HMAC(PSA_ALG_SHA_384)
            * PSA_ALG_HMAC(PSA_ALG_SHA_512)
            * PSA_ALG_HMAC(PSA_ALG_SHA_512_224)
            * PSA_ALG_HMAC(PSA_ALG_SHA_512_256)
    * Asymmetric Signature
        * RSA
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_1)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_224)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_384)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512_224)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512_256)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA3_224)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA3_256)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA3_384)
            * PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA3_512)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_1)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_224)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_256)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_384)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_512)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_512_224)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA_512_256)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA3_224)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA3_256)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA3_384)
            * PSA_ALG_RSA_PSS(PSA_ALG_SHA3_512)
        * ECC
            * Supported curves
                * PSA_ECC_FAMILY_SECP_R1
                    * Key sizes :  256, 384, 521
                * PSA_ECC_FAMILY_BRAINPOOL_P_R1
                    * Key sizes :  256, 320, 384, 512
            * Supported aglorithms
                * PSA_ALG_ECDSA(PSA_ALG_SHA_1)
                * PSA_ALG_ECDSA(PSA_ALG_SHA_224)
                * PSA_ALG_ECDSA(PSA_ALG_SHA_256)
                * PSA_ALG_ECDSA(PSA_ALG_SHA_384)
                * PSA_ALG_ECDSA(PSA_ALG_SHA_512)
                * PSA_ALG_ECDSA(PSA_ALG_SHA_512_224)
                * PSA_ALG_ECDSA(PSA_ALG_SHA_512_256)
                * PSA_ALG_ECDSA(PSA_ALG_SHA3_224)
                * PSA_ALG_ECDSA(PSA_ALG_SHA3_256)
                * PSA_ALG_ECDSA(PSA_ALG_SHA3_384)
                * PSA_ALG_ECDSA(PSA_ALG_SHA3_512)

* Opaque
    * N/A
