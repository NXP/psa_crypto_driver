# MCUXpresso SDK : psa_crypto_driver

## Overview
This repository is for MCUXpresso SDK PSA crypto driver middleware delivery and it contains the components officially provided in NXP MCUXpresso SDK. This repository is part of the MCUXpresso SDK overall delivery which is composed of several sub-repositories/projects. Navigate to the top/parent repository [mcuxsdk](https://github.com/nxp-mcuxpresso/mcuxsdk-manifests/) for the complete delivery of MCUXpresso SDK to be able to build and run the examples that are based on this delivery.

The PSA crypto driver provides the driver interface used to run the PSA cryptographic API on top of NXP crypto hardware IP.

## Documentation
Overall details can be reviewed here: [MCUXpresso SDK Online Documentation](https://mcuxpresso.nxp.com/mcuxsdk/latest/html/introduction/README.html)

## Setup
Instructions on how to install the MCUXpresso SDK provided from GitHub via west manifest [Getting Started with SDK - Detailed Installation Instructions](https://mcuxpresso.nxp.com/mcuxsdk/latest/html/gsd/installation.html#installation)

## Contribution
Contributions are not currently accepted. Guidelines to contribute will be posted in the future.

---------------------------------
## Repo Specific Content

### Usage in Zephyr
Besides the MCUXpresso SDK delivery described above, this repository is also used by Zephyr. It is a Zephyr module (see `zephyr/module.yml`, which declares the module CMake and Kconfig entry points) and is brought into a Zephyr workspace through the NXP HAL (`hal_nxp`), so no separate west entry is required.

In a Zephyr build the port layers are selected through Kconfig. Each option links the corresponding driver library into the application, as defined in `zephyr/CMakeLists.txt`:

| Kconfig option | Port layer | Library target |
| --- | --- | --- |
| `CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC` | ELS PKC | `McuxPsaCryptoDriverElsPkc` |
| `CONFIG_PSA_CRYPTO_DRIVER_SGI_PKC` | SGI PKC | `McuxPsaCryptoDriverSgiPkc` |
| `CONFIG_PSA_CRYPTO_DRIVER_CAAM` | CAAM | `McuxPsaCryptoDriverCaam` |
| `CONFIG_PSA_CRYPTO_DRIVER_DCP` | DCP | `McuxPsaCryptoDriverDcp` |
| `CONFIG_PSA_CRYPTO_DRIVER_ELE_S2XX` | ELE S2XX | `McuxPsaCryptoDriverEleS2xx` |
| `CONFIG_PSA_CRYPTO_DRIVER_ELE_S4xx` | ELE S4xx | `McuxPsaCryptoDriverEleS4xx` |
| `CONFIG_PSA_CRYPTO_DRIVER_CASPER_HASHCRYPT` | Casper / Hashcrypt | `McuxPsaDrvCasperHc` |

These port layers provide hardware acceleration to Mbed TLS through the PSA crypto driver wrappers.

When building with TF-M (`CONFIG_BUILD_WITH_TFM`), the ELS PKC and SGI PKC paths behave differently: instead of linking the driver into the Zephyr application, the SGI PKC option passes `-DCRYPTO_HW_ACCELERATOR=ON` to the TF-M build system.

See `zephyr/Kconfig` and `zephyr/CMakeLists.txt` for the complete and up-to-date list of options, their dependencies, and the threading configuration.

### PSA Key Location
The PSA specification defines multiple key locations (of type `key_location_t`)
that specify the high-level behavior of the key. The default key location
supported by all drivers is the the *Primary Local Storage*.

Other key locations may be supported by specific hardware accelerated ports.
See the [Port Layers](#port-layers) section.

**NOTE: Currently, the PSA reference implementation does not expose**
**vendor-defined key locations. To expose NXP-defined key locations,**
**please include the `mcux_psa_defines.h` header that is contained in the**
**`middleware/mbedtls3x/port/` folder.**

**Properly exposing vendor-defined key locations through the regular**
**inclusion of `psa/crypto.h` is a work in progress.**

#### Primary Local Storage (`PSA_KEY_LOCATION_LOCAL_STORAGE`)
This storage location is defined by PSA as `PSA_KEY_LOCATION_LOCAL_STORAGE` and
is assigned the value of `0`. Keys that are assigned this location are
transparent, so readable in plain text.

#### Other Key Locations (`PSA_KEY_LOCATION_xxx`)
Some drivers may define additional, driver-specific, locations that implement
additional ways of handling opaque key material. Such driver-specific key
locations will be documented in their respective port layer readmes.

### Port Layers
Below is a list of supported port layers with links to their respective readmes.

* [ELE_S200](ele_s200/ele_s200_readme.md)
* CAAM (to be added)
* Casper / Hashcrypt (to be added)
* DCP (to be added)
* ELA_CSEC (to be added)
* [ELE_HSEB](ele_hseb/ele_hseb_readme.md)
* ELE_S4XX (to be added)
* [SGI](sgi/sgi_readme.md)
* [PKC](pkc/pkc_readme.md)
* [ELS_PKC](els_pkc/els_pkc_readme.md)

## License
This repository is under the **BSD-3-Clause** license. See the `LICENSE` file for details.
