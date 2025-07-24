/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** \file mcux_psa_ele_hseb_utils.c
 *
 * This file contains the definitions of the entry points associated
 * with common utility functions utilized by the ELE HSEB PSA port driver.
 */

#include "mcux_psa_ele_hseb_utils.h"

size_t ele_hseb_get_chunk_overflow(size_t chunk_size,
                                   size_t chunk_used_length,
                                   size_t input_length)
{
    const size_t final_length = chunk_used_length + input_length;

    if (final_length > chunk_size) {
        return final_length - chunk_size;
    }
    return 0u;
}

size_t ele_hseb_manage_chunk(uint8_t *chunk,
                             size_t chunk_size,
                             size_t *chunk_length,
                             const uint8_t *input,
                             size_t input_length,
                             bool *is_chunk_full,
                             size_t *overflow)
{
    *overflow = ele_hseb_get_chunk_overflow(chunk_size,
                                            *chunk_length,
                                            input_length);

    const size_t copy_length_without_overflow = input_length - *overflow;
    (void) memcpy((chunk + *chunk_length),
                  input,
                  copy_length_without_overflow);

    *chunk_length += copy_length_without_overflow;
    if (*chunk_length >= chunk_size) {
        *is_chunk_full = true;
    } else {
        *is_chunk_full = false;
    }

    return copy_length_without_overflow;
}
