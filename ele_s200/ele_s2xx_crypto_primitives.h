/*
 * Copyright 2024 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELE_S2XX_CRYPTO_PRIMITIVES_H
#define ELE_S2XX_CRYPTO_PRIMITIVES_H

/** \file ele_s2xx_crypto_primtives.h
 *
 * This file contains the declaration of the context structures related
 * to the ele driver
 *
 */

#include "fsl_sscp_mu.h"
#include "fsl_sss_sscp.h"

typedef struct
{
    sss_sscp_digest_t ctx;
} ele_s2xx_hash_operation_t;

#endif /* ELE_S2XX_CRYPTO_PRIMITIVES_H */
