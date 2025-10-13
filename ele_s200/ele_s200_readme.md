# Key Locations

## `PSA_KEY_LOCATION_LOCAL_STORAGE`

Transparent keys stored in plaintext in the PSA keystore.

### Key Utilization
The general way such keys are utilized for a given crypto operation is:
1. take the plaintext key and import it into the S200,
2. do the crypto operation,
3. delete the key from the S200.

An exception to this are multipart operations, which will keep the given
key in the S200 internal keystore up until the operation is finished or aborted.

## `PSA_KEY_LOCATION_S200_KEY_STORAGE`

EdgeLock2Go opaque key storage. Such a key location cannot be used to generate
new keys on the device and may only be imported with `psa_import_key()`.
The key blobs are then stored in the PSA keystore without modification,
still encrypted. These keys are never readable in plaintext by software.

### Key Utilization
Key Utilization is the same as with `PSA_KEY_LOCATION_LOCAL_STORAGE`.

## `PSA_KEY_LOCATION_S200_KEY_STORAGE_NON_EL2GO`

Generic opaque key storage. This key location may be used with
`psa_generate_key()` to generate opaque keys. Such keys are stored in the PSA
keystore as die-unique encrypted blobs to preserve opacity. These keys are
never readable in plaintext by software.

### Key Utilization
Key Utilization is the same as with `PSA_KEY_LOCATION_LOCAL_STORAGE`.

## `PSA_KEY_LOCATION_S200_DATA_STORAGE`

EdgeLock2Go data storage. The data is unwrapped from the EL2GO blob and placed
into the PSA keystore in plaintext when imported with `psa_import_key()`.
The plaintext data may be retrieved by calling `psa_export_key()`.

# Cryptographic Support for Given Key Locations

* Keyless algorithms
     * Hashes :
          * One-Go: SHA1, SHA224-SHA512, SHA3_224-SHA3_512 **(on KW45 without SHA3)**
          * Multipart: same as One-Go

* `PSA_KEY_LOCATION_LOCAL_STORAGE`
     * Ciphers :
          * Unauthenticated :
               * One-Go :
                    * AES : ECB_NO_PADDING, CBC_NO_PADDING, CTR
          * Authenticated :
               * One-Go :
                    * AES : GCM, CCM
     * MAC :
          * One-Go :
               * CMAC : AES
               * HMAC : SHA1, SHA224-SHA512 **(on KW45 only SHA256)**
          * Multipart : KW47 same as One-Go, KW45 Simulated multipart HMAC via Multipart Hash
     * Asymmetric Cryptography :
          * Sign/Verify Hash :
               * SECP-R1 192-521
               * Brainpool-R1 192, 224, 256, 320, 384, 512 **(on KW47 only)**
          * Sign/Verify Message :
               * Ed25519

* `PSA_KEY_LOCATION_S200_KEY_STORAGE`
     * Ciphers :
          * Unauthenticated :
               * One-Go :
                    * AES : ECB_NO_PADDING, CBC_NO_PADDING, CTR
          * Authenticated :
               * One-Go :
                    * AES : GCM, CCM
     * MAC :
          * One-Go :
               * CMAC : AES
               * HMAC : SHA1, SHA224-SHA512 **(on KW45 only SHA256)**
     * Asymmetric Cryptography :
          * Sign/Verify Hash :
               * SECP-R1 224-521
          * Sign/Verify Message :
               * Ed25519

* `PSA_KEY_LOCATION_S200_KEY_STORAGE_NON_EL2GO`
     * Ciphers :
          * Unauthenticated :
               * One-Go :
                    * AES : ECB_NO_PADDING, CBC_NO_PADDING, CTR
          * Authenticated :
               * One-Go :
                    * AES : GCM, CCM
     * MAC :
          * One-Go :
               * CMAC : AES
               * HMAC : SHA1, SHA224-SHA512 **(on KW45 only SHA256)**
     * Asymmetric Cryptography :
          * Sign/Verify Hash :
               * SECP-R1 192-521
               * Brainpool-R1 192, 224, 256, 320, 384, 512 **(on KW47 only)**
          * Sign/Verify Message :
               * Ed25519, Ed25519ph
