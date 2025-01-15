/*
 * Copyright 2022-2023 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_s2xx_key_generation.c
 *
 * This file contains the implementation of the entry points associated to the
 * key generation (i.e. random generation and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_s2xx_init.h" /* ELE Crypto port layer */
#include "mcux_psa_s2xx_opaque_key_generation.h"
#include "mcux_psa_s2xx_key_locations.h"
#include "mcux_psa_s2xx_common_key_management.h"

psa_status_t ele_s2xx_opaque_import_key(const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length, uint8_t *key_buffer,
    size_t key_buffer_size, size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status      = PSA_ERROR_CORRUPTION_DETECTED;
    sss_sscp_object_t sssKey = {0};

    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

    if (mcux_mutex_lock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    if (false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)))
    {
        psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));
        if (MCUXCLPSADRIVER_IS_S200_BLOB_STORAGE(location))
        {
            // validate blob attributes
            status = ele_s2xx_validate_blob_attributes(attributes, data, data_length);
            if (PSA_SUCCESS != status)
            {
                goto exit;
            }

            // Import
            status = ele_s2xx_import_key(attributes, data, data_length, &sssKey);
            if (PSA_SUCCESS != status)
            {
                goto exit;
            }

            // Store the blob as is in the PSA keystore.
            if (key_buffer_size < data_length)
            {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }

            (void)memcpy(key_buffer, data, data_length);
            *key_buffer_length = data_length;

            status = PSA_SUCCESS;
        }

        if (PSA_ERROR_NOT_SUPPORTED == status)
        {
            *key_buffer_length = data_length;
        }
    }
    else
    {
        /* transparent key location case*/
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_BAD_STATE;
    }

    return status;
}

psa_status_t ele_s2xx_opaque_destroy_key(const psa_key_attributes_t *attributes,
                                         uint8_t *key_buffer,
                                         size_t key_buffer_size)
{
    /* TBD remove key from s200 once new FW without key lock is provided */
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t ele_s2xx_get_buffer_size_from_key_data(const psa_key_attributes_t *attributes,
                                                           const uint8_t *data,
                                                           size_t data_length,
                                                           size_t *key_buffer_length)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));
    psa_status_t status         = PSA_ERROR_CORRUPTION_DETECTED;

    if ((MCUXCLPSADRIVER_IS_S200_BLOB_STORAGE(location)) || (MCUXCLPSADRIVER_IS_S200_ENC_STORAGE(location)))
    {
        *key_buffer_length = data_length;
        status             = PSA_SUCCESS;
    }
    else
    {
        // TBD if other locations are supported, add them
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

size_t ele_s2xx_opaque_size_function(const psa_key_attributes_t *attributes,
                                     const uint8_t *data, size_t data_length)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
                                      psa_get_key_lifetime(attributes));
    size_t key_buffer_size      = 0;
    if (false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)))
    {
        psa_status_t status = ele_s2xx_get_buffer_size_from_key_data(attributes,
                                                                     data,
                                                                     data_length,
                                                                     &key_buffer_size);
        if (PSA_SUCCESS != status)
        {
            key_buffer_size = 0;
        }
    }
    return key_buffer_size;
}

/** @} */ // end of psa_key_generation
