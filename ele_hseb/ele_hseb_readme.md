# ELE HSEB Port for the PSA Crypto API

## Key Management and Key Catalogs

The ELE HSEB component utilizes key catalogs for setting up the internal
keystore. These catalogs may be customized to enable or disable support for
various key types and key sizes. Constraints on these key catalogs may
be found in the HSE API reference manual.

MbedTLS3.x / PSA examples provided in the SDK are using the default key
catalogs, which can be found in the underlying `ele_hseb` component.

Key catalog initialization must therefore be done by the user by utilizing
the `FormatKeyCatalogs()` and `HKF_Init()` functions before using any of the
PSA APIs. During a call to `psa_crypto_init()` it is checked whether key
catalogs have been formatted.

## Supported Algorithms
Below is a list of algorithms supported by the current version of the ELE
HSEB port. Key types and sizes are also specified where relevant.

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
            * CMAC
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
