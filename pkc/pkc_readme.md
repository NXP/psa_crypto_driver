# PKC Component for the PSA Crypto API

## Architecture

The PKC component provides asymmetric cryptography operations using the PKC
(Public Key Cryptography) hardware accelerator. It is a **shared component**
designed to be used alongside a SGI PSA driver that provides
symmetric crypto, hashing, entropy, and key descriptor management.

Dependencies:
* **SGI common key management** - `sgi_create_key_descriptor()` is used to
  build key descriptors for PKC operations.
* **SGI entropy** - `sgi_get_entropy()` is used for random key generation.

### Optional PQC (ML-DSA) Addon

The PKC component optionally supports post-quantum cryptography (PQC) via
ML-DSA (Module-Lattice-Based Digital Signature Algorithm). This support is
disabled by default and must be explicitly enabled via the
`MCUX_COMPONENT_component.psa_crypto_driver.pkc_pqc` Kconfig option, which
in turn selects the `sgi_pkc_pqc` component providing the underlying PQC
primitives. When enabled, ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter
sets are supported for sign message, verify message, key generation, key
import, and public key export.

## Supported ECC Curves

The following ECC curves are supported, each gated by a `PSA_WANT_ECC_*`
compile-time flag:

| Family                          | Key Sizes (bits)          | Condition                             |
|---------------------------------|---------------------------|---------------------------------------|
| `PSA_ECC_FAMILY_SECP_R1`       | 192, 224, 256, 384, 521   | -                                     |
| `PSA_ECC_FAMILY_BRAINPOOL_P_R1`| 256, 384, 512             | -                                     |
| `PSA_ECC_FAMILY_SECP_K1`       | 192, 256                  | Requires `MCUXCL_FEATURE_ECC_SECPK1_CURVES` |

## Supported PQC Algorithms

When the optional PQC addon is enabled, the following ML-DSA parameter
sets are supported:

| Algorithm   | Key Sizes (bits)              |
|-------------|--------------------------------|
| ML-DSA-44   | `PSA_ML_DSA_44_BITS`          |
| ML-DSA-65   | `PSA_ML_DSA_65_BITS`          |
| ML-DSA-87   | `PSA_ML_DSA_87_BITS`          |

**Note:** the PSA_ML_DSA_xx_BITS macros are only provided as placeholders
until the TF-PSA-Crypto core implementation officially supports ML-DSA.

## Supported Operations

### Asymmetric Signature

* Sign Hash (`pkc_sign_hash`):
    * `PSA_ALG_ECDSA` (randomized only; deterministic ECDSA is **not**
      supported and returns `PSA_ERROR_NOT_SUPPORTED`)
    * Requires `PSA_KEY_TYPE_ECC_KEY_PAIR`

* Verify Hash (`pkc_verify_hash`):
    * `PSA_ALG_ECDSA`
    * Accepts both `PSA_KEY_TYPE_ECC_KEY_PAIR` and
      `PSA_KEY_TYPE_ECC_PUBLIC_KEY`
    * For key pairs, the public key is derived internally via the lock-free
      `pkc_internal_export_ecp_public_key()`.

* Sign Message (`pkc_sign_message`) - *PQC addon only*:
    * `PSA_ALG_ML_DSA`
    * Requires `PSA_KEY_TYPE_ML_DSA_KEY_PAIR`
    * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.

* Verify Message (`pkc_verify_message`) - *PQC addon only*:
    * `PSA_ALG_ML_DSA`
    * Accepts both `PSA_KEY_TYPE_ML_DSA_KEY_PAIR` and
      `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY`
    * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.

### Key Generation

* `pkc_generate_key` - generates random ECC key pairs for supported curves.
* `pkc_generate_key` - *PQC addon only* - also generates random ML-DSA key
  pairs (ML-DSA-44, ML-DSA-65, ML-DSA-87).

### Key Import

* *PQC addon only* - importing ML-DSA key pairs and public keys is
  supported via the shared SGI key management infrastructure
  (`sgi_create_key_descriptor()`), for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
  * **NOTE** Until TF-PSA-Crypto has official support for ML-DSA, `psa_import_key()`
    enforces the bits attribute to be set correctly.

### Export Public Key

* `pkc_transparent_export_public_key` - exports the public key in SEC1
  uncompressed point format (`0x04 || X || Y`):
    * For a `PSA_KEY_TYPE_ECC_PUBLIC_KEY` handle the stored point is copied
      out directly (the leading `0x04` uncompressed tag is required).
    * For a `PSA_KEY_TYPE_ECC_KEY_PAIR` handle the public point is derived
      on-chip as `Q = d * G` using the shared secure scalar
	  multiplication helper `sgi_ecc_derive_public_key()`, then the
      `0x04` tag is prepended.
    * *PQC addon only* - for `PSA_KEY_TYPE_ML_DSA_KEY_PAIR` and
      `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` handles, the ML-DSA public key is
      exported in its standalone encoded form.

### Key Agreement

* `pkc_key_agreement` - raw ECDH key agreement
  (`PSA_ALG_IS_RAW_KEY_AGREEMENT`). Returns the raw shared secret; callers
  should chain with a key derivation function for use as key material.

## Additional Features

## Cryptographic Summary

| Operation            | Algorithm                      | Key Types                       | Curves / Parameter Sets                                         |
|----------------------|---------------------------------|----------------------------------|-------------------------------------------------------------------|
| Sign Hash            | `PSA_ALG_ECDSA` (randomized)   | ECC Key Pair                    | SECP_R1, Brainpool_P_R1, SECP_K1                               |
| Verify Hash          | `PSA_ALG_ECDSA`                | ECC Key Pair, Public Key        | SECP_R1, Brainpool_P_R1, SECP_K1                               |
| Key Generation       | -                              | ECC Key Pair                    | SECP_R1, Brainpool_P_R1, SECP_K1                               |
| Export Public Key    | -                              | ECC Key Pair, Public Key        | SECP_R1, Brainpool_P_R1, SECP_K1                               |
| Key Agreement        | `PSA_ALG_ECDH`                 | ECC Key Pair                    | SECP_R1, Brainpool_P_R1, SECP_K1                               |
| Sign Message *(PQC addon)*   | `PSA_ALG_ML_DSA`        | ML-DSA Key Pair                 | ML-DSA-44, ML-DSA-65, ML-DSA-87                                |
| Verify Message *(PQC addon)* | `PSA_ALG_ML_DSA`        | ML-DSA Key Pair, Public Key     | ML-DSA-44, ML-DSA-65, ML-DSA-87                                |
| Key Generation *(PQC addon)* | -                        | ML-DSA Key Pair                 | ML-DSA-44, ML-DSA-65, ML-DSA-87                                |
| Key Import *(PQC addon)*     | -                        | ML-DSA Key Pair, Public Key     | ML-DSA-44, ML-DSA-65, ML-DSA-87                                |
| Export Public Key *(PQC addon)* | -                     | ML-DSA Key Pair, Public Key     | ML-DSA-44, ML-DSA-65, ML-DSA-87                                |
