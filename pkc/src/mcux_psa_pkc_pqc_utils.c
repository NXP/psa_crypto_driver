/*
 * Copyright 2026 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_psa_pkc_pqc_utils.h"

typedef struct _ml_dsa_patch_rng_context_t
{
    const uint8_t *seed;
} ml_dsa_patch_rng_context_t;


static mcuxClRandom_Status_t ml_dsa_seed_rng_patch_fn(
    mcuxClSession_Handle_t session,
    mcuxClRandom_Context_t custom_ctx,
    mcuxCl_Buffer_t out,
    uint32_t out_length
    )
{
    /* Unused */
    (void) session;

    ml_dsa_patch_rng_context_t *ctx = (ml_dsa_patch_rng_context_t *) custom_ctx;

    /* We enforce a 32 Byte seed */
    if (32u != out_length) {
        return MCUXCLRANDOM_STATUS_INVALID_PARAM;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(be_status, be_token, mcuxClBuffer_export(out,
                                                                              0u,
                                                                              ctx->seed,
                                                                              out_length));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_export) != be_token) ||
        (MCUXCLBUFFER_STATUS_OK != be_status)) {
        return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLRANDOM_STATUS_OK;
}

psa_status_t pkc_ml_dsa_generate_key_from_seed(const psa_key_attributes_t *attributes,
                                               const uint8_t *seed,
                                               size_t seed_size,
                                               uint8_t *private_key,
                                               size_t private_key_size,
                                               size_t *private_key_length,
                                               uint8_t *public_key,
                                               size_t public_key_size,
                                               size_t *public_key_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    mcuxClKey_Type_t key_type_priv = { NULL };
    mcuxClKey_Type_t key_type_pub = { NULL };
    const mcuxClKey_GenerationDescriptor_t *key_gen_descriptor = NULL;

    ml_dsa_patch_rng_context_t ctx;
    ctx.seed = seed;

    /* The seed MUST always be 32 Bytes. seed_size is only required as a sanity
     * check for the caller, so they it is never really used, as the RNG patch
     * callback takes 32 Bytes regardless.
     */
    if (seed_size != 32u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_to_pkc_asym_alg_priv(attributes, &key_type_priv);
    if (PSA_SUCCESS != status) {
        return status;
    }

    status = psa_to_pkc_asym_alg_pub(attributes, &key_type_pub);
    if (PSA_SUCCESS != status) {
        return status;
    }

    if ((mcuxClKey_Type_MlDsa44_Private == key_type_priv) &&
        (mcuxClKey_Type_MlDsa44_Public == key_type_pub)) {
        key_gen_descriptor = &mcuxClKey_GenerationDescriptor_MlDsa44;
    } else if ((mcuxClKey_Type_MlDsa65_Private == key_type_priv) &&
               (mcuxClKey_Type_MlDsa65_Public == key_type_pub)) {
        key_gen_descriptor = &mcuxClKey_GenerationDescriptor_MlDsa65;
    } else if ((mcuxClKey_Type_MlDsa87_Private == key_type_priv) &&
               (mcuxClKey_Type_MlDsa87_Public == key_type_pub)) {
        key_gen_descriptor = &mcuxClKey_GenerationDescriptor_MlDsa87;
    } else {
        /* We somehow got mismatched private and public key types */
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    status = get_ml_key_sizes(attributes, private_key_length, public_key_length);
    if (PSA_SUCCESS != status) {
        return status;
    }
    if ((private_key_size < *private_key_length) ||
        (public_key_size < *public_key_length)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Allocate and initialize session */
    /* NOTE: Workarea size is to be specified in bytes (no PKC workarea is used for key generation) */
    mcuxClSession_Descriptor_t session_desc = { 0 };
    mcuxClSession_Handle_t session = &session_desc;

    MCUXCL_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                           MCUXCLMLDSA_MLDSA87_WORKAREASIZE_MAX,
                                           0u, /* No PKC WA is used for keygen */
                                           status, exit);

    /* Allocate space for and initialize private key handle for a ML-DSA private key */
    uint32_t priv_key_desc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    /* MISRA C-2012 Rule 11.3: Intentional per expected CLib usage */
    mcuxClKey_Handle_t priv_key = (mcuxClKey_Handle_t) &priv_key_desc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_status, ki_priv_token,
                                     mcuxClKey_init(session,
                                                    priv_key,
                                                    key_type_priv,
                                                    private_key,
                                                    private_key_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) ||
        (MCUXCLKEY_STATUS_OK != ki_priv_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize public key handle for a ML-DSA public key */
    uint32_t pub_key_desc[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLKEY_DESCRIPTOR_SIZE)];
    /* MISRA C-2012 Rule 11.3: Intentional per expected CLib usage */
    mcuxClKey_Handle_t pub_key = (mcuxClKey_Handle_t) &pub_key_desc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token,
                                     mcuxClKey_init(session,
                                                    pub_key,
                                                    key_type_pub,
                                                    public_key,
                                                    public_key_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) ||
        (MCUXCLKEY_STATUS_OK != ki_pub_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Fill mode descriptor with the relevant data */
    uint32_t
        custom_mode_desc_bytes[(MCUXCLRANDOMMODES_PATCHMODE_DESCRIPTOR_SIZE + (sizeof(uint32_t)) -
                             1U) / sizeof(uint32_t)];
    mcuxClRandom_ModeDescriptor_t *ml_dsa_seed_mode =
        (mcuxClRandom_ModeDescriptor_t *) custom_mode_desc_bytes;
    mcuxClRandomModes_CustomGenerateAlgorithm_t seed_function =
        (mcuxClRandomModes_CustomGenerateAlgorithm_t) &ml_dsa_seed_rng_patch_fn;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cp_status, cp_token,
                                     mcuxClRandomModes_createPatchMode(ml_dsa_seed_mode,
                                                                       seed_function,
                                                                       (mcuxClRandom_Context_t) &ctx,
                                                                       256U));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createPatchMode) != cp_token) ||
        (MCUXCLRANDOM_STATUS_OK != cp_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t context[MCUXCLRANDOMMODES_PATCHMODE_CONTEXT_SIZE_IN_WORDS];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ri_status, init_token,
                                     mcuxClRandom_init(session,
                                                       (mcuxClRandom_Context_t) context,
                                                       ml_dsa_seed_mode));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != init_token) ||
        (MCUXCLRANDOM_STATUS_OK != ri_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(gkp_status, gkp_token,
                                     mcuxClKey_generate_keypair(session,
                                                                key_gen_descriptor,
                                                                priv_key,
                                                                pub_key));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != gkp_token) ||
        (MCUXCLKEY_STATUS_OK != gkp_status)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    status = PSA_SUCCESS;
exit:
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_destroy(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != token) ||
        (MCUXCLSESSION_STATUS_OK != result)) {
        /* Don't override previous success/error, but if we were successful, report corruption */
        if (PSA_SUCCESS == status) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Reset the local seed pointer */
    ctx.seed = NULL;

    return status;
}

psa_status_t get_ml_key_sizes(const psa_key_attributes_t *attributes,
                              size_t *priv_key_size,
                              size_t *pub_key_size)
{
    if (NULL == attributes || NULL == priv_key_size || NULL == pub_key_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status     = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits         = psa_get_key_bits(attributes);

    if (PSA_KEY_TYPE_IS_ML_DSA(key_type)) {
        switch (key_bits) {
            case PSA_ML_DSA_44_BITS:
                *priv_key_size = MCUXCLMLDSA_MLDSA44_SK_LEN;
                *pub_key_size  = MCUXCLMLDSA_MLDSA44_PK_LEN;
                status = PSA_SUCCESS;
                break;
            case PSA_ML_DSA_65_BITS:
                *priv_key_size = MCUXCLMLDSA_MLDSA65_SK_LEN;
                *pub_key_size  = MCUXCLMLDSA_MLDSA65_PK_LEN;
                status = PSA_SUCCESS;
                break;
            case PSA_ML_DSA_87_BITS:
                *priv_key_size = MCUXCLMLDSA_MLDSA87_SK_LEN;
                *pub_key_size  = MCUXCLMLDSA_MLDSA87_PK_LEN;
                status = PSA_SUCCESS;
                break;
            default:
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
        }
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}
