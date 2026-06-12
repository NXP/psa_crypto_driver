# SGI Port for the PSA Crypto API

## Key Locations

This section outlines the different key storage locations supported by the
PSA Crypto API integration with the SGI secure subsystem.

## `PSA_KEY_LOCATION_LOCAL_STORAGE`

Transparent keys stored in plaintext in the PSA keystore.

### Key Utilization

The key material is passed directly to the SGI PKC accelerator for the
requested crypto operation. No additional import/delete cycle into a
hardware keystore is required.

## `PSA_CRYPTO_SGI_LOCATION_DUK_BLOB_STORAGE`

Device-Unique-Key (DUK) opaque blob storage. Keys in this location are
protected at the import/export boundary by sealing them into DUK-encrypted
blobs. At runtime, key material is stored in plaintext in ITS and used
directly for crypto operations.

Each blob carries 12 bytes of metadata:

| Field       | Type         | Description              |
|-------------|--------------|--------------------------|
| `key_alg`   | `uint32_t`   | PSA algorithm            |
| `key_usage` | `uint32_t`   | PSA key usage flags      |
| `key_type`  | `uint16_t`   | PSA key type             |
| `key_bits`  | `uint16_t`   | Key length in bits       |

### Supported Key Types

* `PSA_KEY_TYPE_AES` (128, 192, 256 bit)
* `PSA_KEY_TYPE_HMAC` (any PSA-legal size)
* `PSA_KEY_TYPE_RAW_DATA` (arbitrary length, e.g. BLE IRK)
* `PSA_KEY_TYPE_ECC_KEY_PAIR` (`PSA_ECC_FAMILY_SECP_R1`: 256, 384 bit)

### Supported Operations

* `psa_import_key()` — accepts either plaintext key material or a
  previously exported DUK blob. If a blob is provided it is unsealed to
  recover the plaintext before storing in ITS.
* `psa_export_key()` — reads the plaintext key from ITS, seals it into a
  DUK blob, and returns the blob to the caller.
* `psa_export_public_key()` — derives the public key from the plaintext
  ECC private key stored in ITS.
* `psa_generate_key()` — generates random key material and stores the
  plaintext in ITS.
* `psa_key_derivation_output_key()` — derives key material and stores the
  plaintext in ITS.

### Blob Wrapping Key

The blob wrapping key is selected at build time:
* If `MCUXCL_FEATURE_KEY_DERIVATION` is defined, the Subsystem Resident
  Sealing Key (SSRK) is derived via CKDF and cached for the lifetime of the
  session. It can be zeroized explicitly by calling `sgi_ssrk_zeroize()`
  (e.g. on `psa_crypto_deinit()`).
* Otherwise, the DUK stored in SGI coprocessor slot 6 is used directly.

### Key Utilization

Since keys in this location are stored as plaintext in ITS at runtime,
crypto operations (cipher, AEAD, MAC, sign/verify) use the plaintext
key buffer directly — the same path as `PSA_KEY_LOCATION_LOCAL_STORAGE`.
  # Additional Optional Features

  * **Double cipher with CMAC verification** — When enabled, cipher
    encrypt/decrypt operations are performed twice and verified using
    AES-128-CMAC to detect potential fault injection attacks. This feature is
    enabled through the
    `MCUX_COMPONENT_component.psa_crypto_driver.sgi.feature.double_cipher_enable`
    Kconfig option.

    *Disabled by default*.
# Cryptographic Support for Given Key Locations

## Keyless Algorithms

* Hash
    * One-Go and Multipart:
        * `PSA_ALG_SHA_224`
        * `PSA_ALG_SHA_256`
        * `PSA_ALG_SHA_384`
        * `PSA_ALG_SHA_512`

## `PSA_KEY_LOCATION_LOCAL_STORAGE`

* Cipher
    * Unauthenticated
        * One-Go:
            * AES: `PSA_ALG_ECB_NO_PADDING`, `PSA_ALG_CBC_NO_PADDING`,
              `PSA_ALG_CTR`
    * Authenticated (AEAD)
        * One-Go:
            * AES: `PSA_ALG_GCM`, `PSA_ALG_CCM`
* MAC
    * One-Go:
        * `PSA_ALG_CMAC` (AES)
        * `PSA_ALG_HMAC(PSA_ALG_SHA_256)`
        * `PSA_ALG_HMAC(PSA_ALG_SHA_384)`
        * `PSA_ALG_HMAC(PSA_ALG_SHA_512)`
* Asymmetric Cryptography
    * Sign / Verify Hash:
        * `PSA_ALG_ECDSA` with `PSA_ECC_FAMILY_SECP_R1` (256, 384 bit)
