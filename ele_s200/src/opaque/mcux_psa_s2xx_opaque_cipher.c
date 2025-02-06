/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** \file mcux_psa_s2xx_opaque_cipher.c
 *
 * This file contains the implementation of the entry points associated to the
 * cipher capability (single-part only, multi-part (not supported in ele) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "mcux_psa_s2xx_common_init.h"
#include "mcux_psa_s2xx_opaque_cipher.h"
#include "mcux_psa_s2xx_key_locations.h"
#include "mcux_psa_s2xx_common_key_management.h"

// TODO move static functions to the common layer
//      most, if not all, should be the same for transparent ciphers too

static psa_status_t psa_to_s200_alg(psa_key_type_t key_type, psa_algorithm_t alg, sss_algorithm_t *ele_algo)
{
    switch (key_type)
    {
#if defined(PSA_WANT_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            switch (alg)
            {
#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
                case PSA_ALG_CBC_NO_PADDING:
                    *ele_algo = kAlgorithm_SSS_AES_CBC;
                    break;
#endif /* PSA_WANT_ALG_CBC_NO_PADDING */
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
                case PSA_ALG_ECB_NO_PADDING:
                    *ele_algo = kAlgorithm_SSS_AES_ECB;
                    break;
#endif /* PSA_WANT_ALG_ECB_NO_PADDING */
#if defined(PSA_WANT_ALG_CTR)
                case PSA_ALG_CTR:
                    *ele_algo = kAlgorithm_SSS_AES_CTR;
                    break;
#endif /* PSA_WANT_ALG_CTR */
                default:
                    return PSA_ERROR_NOT_SUPPORTED;
            } /* operation->alg */
            break;
#endif        /* PSA_WANT_KEY_TYPE_AES */
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

static psa_status_t ele_s2xx_cipher_arg_validation(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length,
    sss_mode_t mode)
{
    /* Key buffer or size can't be NULL */
    if (!key_buffer || !key_buffer_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Algorithm needs to be a CIPHER algo */
    if (!PSA_ALG_IS_CIPHER(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check permissions for EL2GO keys, as those checks were skipped in common layer */
    if (PSA_ALG_IS_VENDOR_DEFINED(psa_get_key_algorithm(attributes)))
    {
        if (ALG_NXP_ALL_CIPHER != psa_get_key_algorithm(attributes))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    /* Special validation cases for encryption */
    if (kMode_SSS_Encrypt == mode)
    {
        /* Output buffer has to be atleast Input buffer size */
        if (output_size < input_length)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        /* IV buffer can't be NULL or size 0 */
        if ((PSA_ALG_CBC_NO_PADDING == alg) || (PSA_ALG_CTR == alg))
        {
            if (!iv || !iv_length)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }

    /* If input length or input buffer NULL, it's an error.
     * Special case for ECB where input = 0 may be allowed.
     * Taken care of in above code.
     */
    if (!input_length || !input)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Output buffer can't be NULL */
    if (!output || !output_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* For CBC and ECB No padding, input length has to be multiple of cipher block length */
    if ((alg == PSA_ALG_CBC_NO_PADDING || alg == PSA_ALG_ECB_NO_PADDING) &&
        input_length % PSA_BLOCK_CIPHER_BLOCK_LENGTH(psa_get_key_type(attributes)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t key_management(const psa_key_attributes_t *attributes,
                                   const uint8_t *key_buffer,
                                   size_t key_buffer_size,
                                   sss_sscp_object_t *sssKey)
{
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;

    /* Validate if the key is a blob */
    psa_status = ele_s2xx_validate_blob_attributes(attributes, key_buffer, key_buffer_size);
    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    /* Import the key */
    psa_status = ele_s2xx_import_key(attributes, key_buffer, key_buffer_size, sssKey);
    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    return PSA_SUCCESS;
}

static psa_status_t do_cipher(sss_sscp_object_t *sssKey,
                              const uint8_t *iv, size_t iv_length,
                              const uint8_t *input, uint8_t *output,
                              size_t input_length,
                              sss_algorithm_t ele_algo, sss_mode_t mode)
{
    sss_sscp_symmetric_t ctx = {0};

    /* Init symmetric context */
    if (sss_sscp_symmetric_context_init(&ctx, &g_ele_ctx.sssSession,
                                        sssKey, ele_algo,
                                        mode) != kStatus_SSS_Success)
    {
        (void)sss_sscp_key_object_free(sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Run encryption */
    if (sss_sscp_cipher_one_go(&ctx, (uint8_t *)iv,
                               iv_length, input,
                               output, input_length) != kStatus_SSS_Success)
    {
        (void)sss_sscp_symmetric_context_free(&ctx);
        (void)sss_sscp_key_object_free(sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Clean up */
    if (sss_sscp_symmetric_context_free(&ctx) != kStatus_SSS_Success)
    {
        (void)sss_sscp_key_object_free(sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

psa_status_t ele_s2xx_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;

    sss_algorithm_t ele_algo = 0;
    sss_sscp_object_t sssKey = {0};

    psa_status = psa_to_s200_alg(key_type, alg, &ele_algo);
    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    psa_status = ele_s2xx_cipher_arg_validation(attributes, key_buffer,
                                            key_buffer_size, alg, iv, iv_length,
                                            input, input_length, output,
                                            output_size, output_length,
                                            kMode_SSS_Encrypt);
    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    /* PSA specification is not very clear on 0 input for ECB.
     * However software implementation and the tests return SUCCESS
     * for 0 input. So adding this check here.
     */
    if ((PSA_ALG_ECB_NO_PADDING == alg) && (0 == input_length))
    {
        *output_length = 0;
        return PSA_SUCCESS;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    /* Handle key import */
    psa_status = key_management(attributes, key_buffer, key_buffer_size, &sssKey);
    if (PSA_SUCCESS != psa_status)
    {
        goto exit;
    }

    psa_status = do_cipher(&sssKey, iv, iv_length, input, output,
                           input_length, ele_algo, kMode_SSS_Encrypt);
    if (PSA_SUCCESS != psa_status)
    {
        goto exit;
    }

    *output_length = input_length;

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_BAD_STATE;
    }

    return psa_status;
}

psa_status_t ele_s2xx_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_status_t status     = PSA_ERROR_CORRUPTION_DETECTED;

    sss_algorithm_t ele_algo = 0;
    sss_sscp_object_t sssKey = {0};

    uint32_t iv_length          = 0;
    uint32_t expected_op_length = 0;

    status = psa_to_s200_alg(key_type, alg, &ele_algo);
    if (PSA_SUCCESS != status)
    {
        return status;
    }

    status = ele_s2xx_cipher_arg_validation(attributes, key_buffer,
                                            key_buffer_size, alg, NULL, 0,
                                            input, input_length, output,
                                            output_size, output_length,
                                            kMode_SSS_Decrypt);
    if (PSA_SUCCESS != status)
    {
        return status;
    }

    /* PSA specification is not very clear on 0 input for ECB.
     * However software implementation and the tests return SUCCESS
     * for 0 input. So adding this check here.
     */
    if ((PSA_ALG_ECB_NO_PADDING == alg) && (0 == input_length))
    {
        *output_length = 0;
        return PSA_SUCCESS;
    }

    /* Find the IV length for key type and algorithm */
    iv_length = PSA_CIPHER_IV_LENGTH(key_type, alg);

    /* Input buffer -> IV + INPUT.
     * So output length would be (input - iv_length)
     */
    expected_op_length = input_length - iv_length;
    if (output_size < expected_op_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mcux_mutex_lock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    /* Handle key import */
    status = key_management(attributes, key_buffer, key_buffer_size, &sssKey);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    status = do_cipher(&sssKey, input, iv_length, (input + iv_length),
                           output, input_length, ele_algo, kMode_SSS_Decrypt);
    if (PSA_SUCCESS != status)
    {
        goto exit;
    }

    *output_length = expected_op_length;

exit:
    if (mcux_mutex_unlock(&ele_hwcrypto_mutex))
    {
        return PSA_ERROR_BAD_STATE;
    }

    return status;
}
