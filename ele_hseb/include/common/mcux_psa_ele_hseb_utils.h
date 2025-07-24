/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_ELE_HSEB_UTILS_H
#define MCUX_PSA_ELE_HSEB_UTILS_H

/** \file mcux_psa_ele_hseb_utils.h
 *
 * This file contains the declaration of the entry points associated
 * with common utility functions utilized by the ELE HSEB PSA port driver.
 *
 * \note This header should not be included by ele_hseb.h, as it is internal
 *       only.
 *
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Given a chunk size, an already used chunk length and some input size,
 *        return the remainder of the input length that does not fit into chunk
 *
 * \param[in] chunk_size        Size of the chunk buffer
 * \param[in] chunk_used_length Already used length of the buffer
 * \param[in] input_length      Length of the input to be moved into the buffer
 *
 * \retval Byte length of overflowing (i.e. not moved) input if it were moved
 *         to the buffer
 */
size_t ele_hseb_get_chunk_overflow(size_t chunk_size,
                                   size_t chunk_used_length,
                                   size_t input_length);

/**
 * \brief Unprocessed chunk management for multipart operations
 *
 * Takes the \ref chunk buffer with its parameters and moves as much
 * of the \ref input as possible. If the \ref input_length to be moved is
 * longer than the available size of the \ref chunk, the overflow is returned
 * in \ref overflow.
 *
 * \param[in,out] chunk         The chunk buffer
 * \param[in]     chunk_size    Size of the chunk buffer
 * \param[in,out] chunk_length  Already used length of the buffer as input,
 *                              and the resulting length of the chunk as
 *                              output
 * \param[in]     input         Input to be moved to the chunk buffer
 * \param[in]     input_length  Length of the input to be moved into the
 *                              buffer
 * \param[out]    is_chunk_full Flag whether the chunk buffer is full
 * \param[out]    overflow      Byte length of input not moved to the chunk
 *
 * \retval Byte length of the input that has been moved to the chunk buffer
 */
size_t ele_hseb_manage_chunk(uint8_t *chunk,
                             size_t chunk_size,
                             size_t *chunk_length,
                             const uint8_t *input,
                             size_t input_length,
                             bool *is_chunk_full,
                             size_t *overflow);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_ELE_HSEB_UTILS_H */
