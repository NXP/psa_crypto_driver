/*
 * Copyright 2022-2023 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_s4xx_key_agreement.c
 *
 * This file contains the implementation of the entry points associated to the
 * key agreement (i.e. random agreement and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_s4xx_key_agreement.h"
#include "mcux_psa_s4xx_common_key_management.h"
#include "mcux_psa_s4xx_init.h"

#include "psa/crypto.h"
#include "mbedtls/asn1write.h"


psa_status_t ele_s4xx_transparent_key_agreement(const psa_key_attributes_t *attributes,
        										const uint8_t *key_buffer,
												size_t key_buffer_size,
												psa_algorithm_t alg,
												const uint8_t *peer_key,
												size_t peer_key_size,
												uint8_t *shared_secret,
												size_t shared_secret_size,
												size_t *shared_secret_length)
{

	    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	    status_t ele_status = kStatus_Fail;
	    ele_ecdh_t ecdh_conf = {0};
	    uint32_t secret_size = 0;

	    /* Algorithm needs to be a ECDH algo. If not return NOT supported to enable SW Fallback. */
	    if (!PSA_ALG_IS_ECDH(alg)) {
	        return PSA_ERROR_NOT_SUPPORTED;
	    }

	    /* Key buffer or size can't be NULL */
	    if (!key_buffer || !key_buffer_size) {
	        return PSA_ERROR_INVALID_ARGUMENT;
	    }

	    /* Peer Key buffer can't be NULL. Peer key size must be greater than 64 bytes to use NIST-P curves. */
	    if (!peer_key || (peer_key_size<64)) {
	        return PSA_ERROR_INVALID_ARGUMENT;
	    }

	    /* Peer Key buffer or size can't be NULL */
		if (!shared_secret || !shared_secret_size) {
		    return PSA_ERROR_INVALID_ARGUMENT;
		}

	    switch (key_buffer_size) {
	    	case 32:
	    		ecdh_conf.key_size_bits = kECDH_P256;
	    		break;
	        case 48:
	        	ecdh_conf.key_size_bits = kECDH_P384;
	        	break;
	        case 66:
	        	ecdh_conf.key_size_bits = kECDH_P521;
	        	break;
	        default:
	        	return PSA_ERROR_NOT_SUPPORTED;
	    }

	    // Public key size is two times master key + header in NIST P curves)
	    if(peer_key_size%key_buffer_size)
	    {
			// ELE ECDH only supports NIST P curves. The key starts with 0x4 which must be stripped off in ELE buffer.
			ecdh_conf.public_key = &peer_key[1];
			ecdh_conf.public_key_size = peer_key_size-1;
	    }
	    else
	    {
	    	ecdh_conf.public_key = peer_key;
	    	ecdh_conf.public_key_size = peer_key_size;
	    }

		ecdh_conf.operation = kECDH;
		ecdh_conf.private_key = key_buffer;
		ecdh_conf.private_key_size = key_buffer_size;
		ecdh_conf.shared_secret = shared_secret;
		ecdh_conf.shared_secret_size = shared_secret_size;

	    if (mcux_mutex_lock(&ele_hwcrypto_mutex)) {
	        return PSA_ERROR_COMMUNICATION_FAILURE;
	    }

		ele_status = ELE_Ecdh(S3MU, &ecdh_conf, &secret_size);
	    status = ele_to_psa_status(ele_status);

	    if (mcux_mutex_unlock(&ele_hwcrypto_mutex)) {
	        return PSA_ERROR_BAD_STATE;
	    }

	    if (status == PSA_SUCCESS) {
	        *shared_secret_length = secret_size;
	    }

	    return status;
}


/** @} */ // end of psa_key_agreement
