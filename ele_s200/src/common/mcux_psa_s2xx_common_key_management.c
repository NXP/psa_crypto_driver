/*
 * Copyright 2025 NXP
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** \file mcux_psa_s2xx_common_key_management.c
 *
 * This file contains the definitions of the entry points associated to
 * common S2XX key management procedures.
 *
 */

#include "mcux_psa_s2xx_common_key_management.h"


#if (defined(ELEMU_HAS_LOADABLE_FW) && ELEMU_HAS_LOADABLE_FW)
extern const uint8_t fw[];
#endif /* ELEMU_HAS_LOADABLE_FW */

// PSA command context
typedef struct psa_cmd_s
{
    psa_key_attributes_t attributes;
    const uint8_t *magic;
    size_t magic_size;
    uint32_t wrapping_key_id;
    uint32_t wrapping_algorithm;
    const uint8_t *iv;
    size_t iv_size;
    uint32_t signature_key_id;
    uint32_t signature_algorithm;
    const uint8_t *keyincmd;
    size_t keyincmd_size;
    const uint8_t *signature;
    size_t signature_size;
} psa_cmd_t;

typedef struct
{
    uint32_t magic;                  /*! offset 0x00: Fixed 4-byte string of 'sbv3' without the
                                        trailing NULL */
    uint32_t formatVersion;          /*! offset 0x04: (major = 3, minor = 0); The format
                                        version determines the header block size. */
    uint32_t flags;                  /*! offset 0x08: not defined yet, keep zero for future
                                        compatibility */
    uint32_t blockCount;             /*! offset 0x0C: Number of blocks not including the
                                        header block. */
    uint32_t blockSize;              /*! offset 0x10: Size in bytes of all subsequent blocks. */
    uint32_t timeStamp[2];           /*! offset 0x14: 64-bit timestamp in microseconds since
                                        1-1-2000 00:00 when the image was created. */
    uint32_t firmwareVersion;        /*! offset 0x1c: Version number of the included
                                        firmware */
    uint32_t imageTotalLength;       /*! offset 0x20: total image length in bytes,
                                        including signatures etc. */
    uint32_t imageType;              /*! offset 0x24: image type and flags */
    uint32_t certificateBlockOffset; /*! offset 0x28: Offset from start of header
                                        block to the certificate block. This
                                        allows the signed image verification code
                                        to verify the signature over the header
                                        block. */
    uint8_t decription[16];          /*! text description of SB3.1 file */
} nboot_sb3_header_t;

// Tags used in PSA commands
#define PSA_CMD_TAG_MAGIC               0x40U
#define PSA_CMD_TAG_KEY_ID              0x41U
#define PSA_CMD_TAG_PERMITTED_ALGORITHM 0x42U
#define PSA_CMD_TAG_KEY_USAGE_FLAGS     0x43U
#define PSA_CMD_TAG_KEY_TYPE            0x44U
#define PSA_CMD_TAG_KEY_BITS            0x45U
#define PSA_CMD_TAG_KEY_LIFETIME        0x46U
#define PSA_CMD_TAG_KEY_LIFECYCLE       0x47U
#define PSA_CMD_TAG_WRAPPING_KEY_ID     0x50U
#define PSA_CMD_TAG_WRAPPING_ALGORITHM  0x51U
#define PSA_CMD_TAG_IV                  0x52U
#define PSA_CMD_TAG_SIGNATURE_KEY_ID    0x53U
#define PSA_CMD_TAG_SIGNATURE_ALGORITHM 0x54U
#define PSA_CMD_TAG_KEYIN_CMD           0x55U
#define PSA_CMD_TAG_SIGNATURE           0x5EU

// Algorithms used in EL2GO blobs
#define BLOB_SIGN_ALGORITHM_CMAC    0x01U
#define BLOB_WRAP_ALGORITHM_RFC3394 0x01U
#define BLOB_WRAP_ALGORITHM_AES_CBC 0x02U

#define NXP_DIE_EL2GOIMPORT_AUTH_SK_ID   0x7FFF8170U

#define CMAC_BLOCK_SIZE 16U

#ifndef PSA_DRIVER_ERROR
#define PSA_DRIVER_ERROR(...)                                \
    for (;;)                                                 \
    {                                                        \
        (void)PRINTF("ERROR: %s L#%d ", __func__, __LINE__); \
        (void)PRINTF(__VA_ARGS__);                           \
        (void)PRINTF("\r\n");                                \
        break;                                               \
    }
#endif /* PSA_DRIVER_ERROR */

#define PSA_DRIVER_EXIT_STATUS_MSG(STATUS, ...) \
    psa_status = STATUS;                        \
    PSA_DRIVER_ERROR(__VA_ARGS__);              \
    goto exit;

#define PSA_DRIVER_SUCCESS_OR_EXIT_MSG(...) \
    if (PSA_SUCCESS != psa_status)          \
    {                                       \
        PSA_DRIVER_ERROR(__VA_ARGS__);      \
        goto exit;                          \
    }

#define PSA_DRIVER_SUCCESS_OR_EXIT() PSA_DRIVER_SUCCESS_OR_EXIT_MSG("psa_status is not success but [0x%x]", psa_status)


#define PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(CONDITION, STATUS, ...) \
    if (!(CONDITION))                                                \
    {                                                                \
        PSA_DRIVER_EXIT_STATUS_MSG(STATUS, __VA_ARGS__);             \
    }

/** @brief Gets the 32-bit value from the value buffer.
 *
 */
static uint32_t get_uint32_val(const uint8_t *input)
{
    uint32_t output = 0U;
    output          = *(input);
    output <<= 8;
    output |= *(input + 1u);
    output <<= 8;
    output |= *(input + 2u);
    output <<= 8;
    output |= *(input + 3u);
    return output;
}

/** @brief Gets the 16-bit value from the value buffer.
 *
 */
static uint16_t get_uint16_val(const uint8_t *input)
{
    uint16_t output = 0U;
    output          = *input;
    output <<= 8;
    output |= *(input + 1u);
    return output;
}

// Function taken from MbedTLS
static int get_len(const unsigned char **p, const unsigned char *end, size_t *len)
{
    if ((end - *p) < 1)
    {
        return (PSA_ERROR_INVALID_ARGUMENT);
    }

    if ((**p & 0x80u) == 0u)
    {
        *len = *(*p)++;
    }
    else
    {
        switch (**p & 0x7Fu)
        {
            case 1:
                if ((end - *p) < 2)
                {
                    return (PSA_ERROR_INVALID_ARGUMENT);
                }

                *len = (*p)[1];
                (*p) += 2;
                break;

            case 2:
                if ((end - *p) < 3)
                {
                    return (PSA_ERROR_INVALID_ARGUMENT);
                }

                *len = ((size_t)(*p)[1] << 8) | (*p)[2];
                (*p) += 3;
                break;

            case 3:
                if ((end - *p) < 4)
                {
                    return (PSA_ERROR_INVALID_ARGUMENT);
                }

                *len = ((size_t)(*p)[1] << 16) | ((size_t)(*p)[2] << 8) | (*p)[3];
                (*p) += 4;
                break;

            case 4:
                if ((end - *p) < 5)
                {
                    return (PSA_ERROR_INVALID_ARGUMENT);
                }

                *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) | ((size_t)(*p)[3] << 8) | (*p)[4];
                (*p) += 5;
                break;

            default:
                return (PSA_ERROR_INVALID_ARGUMENT);
        }
    }
    if (*len > (size_t)(end - *p))
    {
        return (PSA_ERROR_INVALID_ARGUMENT);
    }
    return (0);
}

// Function taken from MbedTLS
static int get_tag(const unsigned char **p, const unsigned char *end, size_t *len, uint8_t tag)
{
    if ((end - *p) < 1)
    {
        return (PSA_ERROR_INVALID_ARGUMENT);
    }

    if (**p != tag)
    {
        return (PSA_ERROR_INVALID_ARGUMENT);
    }

    (*p)++;

    return (get_len(p, end, len));
}

static psa_status_t get_ele_fw_version(uint8_t *ele_fw_version)
{
    sss_mgmt_t mgmtContext  = {0u};
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;

    size_t datalen = 8u;

    /* PropertyId of Edgelock Firmware version */
    uint32_t propertyId = 0x51u;

    do
    {
        if (sss_mgmt_context_init(&mgmtContext, &g_ele_ctx.sssSession) != kStatus_SSS_Success)
        {
            break;
        }

        /* READ FUSE */
        if (sss_mgmt_get_property(&mgmtContext, propertyId, ele_fw_version, &datalen) != kStatus_SSS_Success)
        {
            break;
        }

        /* If all steps before passes without break, then consider it as success*/
        psa_status = PSA_SUCCESS;

    } while (false);

    /* FREE MGMT CONTEXT */
    sss_mgmt_context_free(&mgmtContext);

    return psa_status;
}

static psa_status_t ele2go_fw_loaded()
{
    uint32_t ele_version[2];

    /* ELE will respond with 0x1010001E99485FD if EL2go FW  KW45_A1_A2_SDK_FW_1_1_0_3 is loaded*/
    static const uint32_t el2go_fw_loaded[2] = {0x1010001, 0xE99485FD};

    if (get_ele_fw_version((uint8_t *)ele_version) != PSA_SUCCESS )
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    if (memcmp(el2go_fw_loaded, ele_version, sizeof(el2go_fw_loaded)) == 0)
    {
        /* correct FW is loaded*/
        return PSA_SUCCESS;
    }
    else
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Unreachable */
    return PSA_ERROR_GENERIC_ERROR;
}

static psa_status_t parse_psa_import_command(const uint8_t *data, size_t data_size, psa_cmd_t *psa_cmd)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;

    uint8_t tag    = 0U; // the tag of the current TLV
    size_t cmd_len = 0U; // the length of the current TLV

    const uint8_t *cmd_ptr = NULL;
    const uint8_t *end     = NULL;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(data != NULL, PSA_ERROR_INVALID_ARGUMENT, "The command is null");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_cmd != NULL, PSA_ERROR_INVALID_ARGUMENT,
                                         "The key attributes context is null");

    (void)memset(psa_cmd, 0, sizeof(psa_cmd_t));
    psa_cmd->attributes = psa_key_attributes_init();

    cmd_ptr = data;
    end     = cmd_ptr + data_size;

    while ((cmd_ptr + 1) < end)
    {
        tag        = *cmd_ptr;
        psa_status = get_tag(&cmd_ptr, end, &cmd_len, tag);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("get_tag failed: 0x%x", psa_status);

        switch (tag)
        {
            case PSA_CMD_TAG_MAGIC:
                psa_cmd->magic      = cmd_ptr;
                psa_cmd->magic_size = cmd_len;
                break;
            case PSA_CMD_TAG_KEY_ID:
                psa_set_key_id(&psa_cmd->attributes, mbedtls_svc_key_id_make(0, (psa_key_id_t)get_uint32_val(cmd_ptr)));
                break;
            case PSA_CMD_TAG_PERMITTED_ALGORITHM:
                psa_set_key_algorithm(&psa_cmd->attributes, (psa_algorithm_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_USAGE_FLAGS:
                psa_set_key_usage_flags(&psa_cmd->attributes, (psa_key_usage_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_TYPE:
                psa_set_key_type(&psa_cmd->attributes, (psa_key_type_t)get_uint16_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_BITS:
                psa_set_key_bits(&psa_cmd->attributes, (size_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_LIFETIME:
                psa_set_key_lifetime(&psa_cmd->attributes, (psa_key_lifetime_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_LIFECYCLE:
                /* Nothing to do */
                break;
            case PSA_CMD_TAG_WRAPPING_KEY_ID:
                psa_cmd->wrapping_key_id = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_WRAPPING_ALGORITHM:
                psa_cmd->wrapping_algorithm = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_IV:
                psa_cmd->iv      = cmd_ptr;
                psa_cmd->iv_size = cmd_len;
                break;
            case PSA_CMD_TAG_SIGNATURE_KEY_ID:
                psa_cmd->signature_key_id = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_SIGNATURE_ALGORITHM:
                psa_cmd->signature_algorithm = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_KEYIN_CMD:
                psa_cmd->keyincmd      = cmd_ptr;
                psa_cmd->keyincmd_size = cmd_len;
                break;
            case PSA_CMD_TAG_SIGNATURE:
                psa_cmd->signature      = cmd_ptr;
                psa_cmd->signature_size = cmd_len;
                break;
            default:
                PSA_DRIVER_ERROR("Unknown tag: 0x%x", tag);
                break;
        }
        cmd_ptr += cmd_len;
    }

exit:

    return psa_status;
}


psa_status_t ele_s2xx_import_key(const psa_key_attributes_t *attributes,
                                 const uint8_t *blob, size_t blob_size,
                                 sss_sscp_object_t *sssKey)
{
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;

    /* Check if EL2go FW is loaded into S200; if not load it */
    if (ele2go_fw_loaded() != PSA_SUCCESS)
    {
#if (defined(ELEMU_HAS_LOADABLE_FW) && ELEMU_HAS_LOADABLE_FW)
        if (ELEMU_loadFw(ELEMUA, (uint32_t *)fw) != kStatus_Success)
        {
            psa_status = PSA_ERROR_HARDWARE_FAILURE;
        }
#else /* ELEMU_HAS_LOADABLE_FW */
        psa_status = PSA_ERROR_NOT_SUPPORTED;
#endif /* ELEMU_HAS_LOADABLE_FW */
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error, loadFW() failed");
    }

    /* Import blob into S200, if operation end with succes blob is valid */

    if (sss_sscp_key_object_init(sssKey, &g_ele_ctx.keyStore) != kStatus_SSS_Success)
    {
        psa_status = PSA_ERROR_HARDWARE_FAILURE;
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error, Keyobject init failed");
    }

    /* Use the PSA key ID as the S200 key ID - easier to keep track of it */
    if (sss_sscp_key_object_allocate_handle(sssKey, psa_get_key_id(attributes),
                                            kSSS_KeyPart_Default, kSSS_CipherType_AES,
                                            PSA_BITS_TO_BYTES(psa_get_key_bits(attributes)),
                                            kSSS_KeyProp_CryptoAlgo_AES) != kStatus_SSS_Success)
    {
        psa_status = PSA_ERROR_HARDWARE_FAILURE;
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error, Allocating handle failed");
    }

    /* Load key from EL2GO Blob to also let the s2xx validate the blob */
    if (sss_sscp_key_store_import_key(&g_ele_ctx.keyStore, sssKey, blob, blob_size, 0, kSSS_blobType_EL2GO_TLV_blob) != kStatus_SSS_Success)
    {
        psa_status = PSA_ERROR_HARDWARE_FAILURE;
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error, Blob import failed");
    }

    psa_status = PSA_SUCCESS;
exit:
    return psa_status;
}

/* Modified from mcuxClPsaDriver_Oracle_Utils_ValidateBlobAttributes() */
/* Take the blob attribs + the given PSA key attribs and check if they match. */
psa_status_t ele_s2xx_validate_blob_attributes(const psa_key_attributes_t *attributes,
                                               const uint8_t *psa_import_blob,
                                               size_t psa_import_blob_size)
{
    psa_status_t psa_status = PSA_SUCCESS;

    psa_cmd_t psa_cmd;
    psa_status = parse_psa_import_command(psa_import_blob, psa_import_blob_size, &psa_cmd);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error while parsing import blob");

    // Validate input PSA attributes
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(0 == mbedtls_svc_key_id_is_null(psa_get_key_id(attributes)),
                                         PSA_ERROR_INVALID_ARGUMENT, "Invalid input key_id");

    // Attention: Permitted algorithm can be 0 (PSA_ALG_NONE for X.509/Binary)
    // Attention: Permitted usage can be 0 (PSA_KEY_USAGE_NONE for static public keys)

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_get_key_type(attributes) != (psa_key_type_t)0, PSA_ERROR_INVALID_ARGUMENT,
                                         "Invalid input key_type");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_get_key_bits(attributes) != (size_t)0, PSA_ERROR_INVALID_ARGUMENT,
                                         "Invalid input key_length");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_get_key_lifetime(attributes) != (psa_key_lifetime_t)0,
                                         PSA_ERROR_INVALID_ARGUMENT, "Invalid input key_lifetime");

    // Validate blob PSA attributes
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(MBEDTLS_SVC_KEY_ID_GET_KEY_ID(psa_get_key_id(attributes)) ==
                                             MBEDTLS_SVC_KEY_ID_GET_KEY_ID(psa_get_key_id(&psa_cmd.attributes)),
                                         PSA_ERROR_INVALID_ARGUMENT, "provided key_id does not match with blob key_id");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        psa_get_key_algorithm(attributes) == psa_get_key_algorithm(&psa_cmd.attributes), PSA_ERROR_INVALID_ARGUMENT,
        "provided permitted_alg does not match with blob permitted_alg");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        psa_get_key_usage_flags(attributes) == psa_get_key_usage_flags(&psa_cmd.attributes), PSA_ERROR_INVALID_ARGUMENT,
        "provided key_usage does not match with blob key_usage");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_get_key_type(attributes) == psa_get_key_type(&psa_cmd.attributes),
                                         PSA_ERROR_INVALID_ARGUMENT,
                                         "provided key_type does not match with blob key_type");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_get_key_bits(attributes) == psa_get_key_bits(&psa_cmd.attributes),
                                         PSA_ERROR_INVALID_ARGUMENT,
                                         "provided key_length does not match with blob key_length");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_get_key_lifetime(attributes) == psa_get_key_lifetime(&psa_cmd.attributes),
                                         PSA_ERROR_INVALID_ARGUMENT,
                                         "provided key_lifetime does not match with blob key_lifetime");


    // Validate signature parameters
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(NXP_DIE_EL2GOIMPORT_AUTH_SK_ID == psa_cmd.signature_key_id,
                                         PSA_ERROR_INVALID_ARGUMENT, "Unknown blob signature_key_id");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(BLOB_SIGN_ALGORITHM_CMAC == psa_cmd.signature_algorithm,
                                         PSA_ERROR_INVALID_ARGUMENT, "Unknown blob signature_algorithm");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(CMAC_BLOCK_SIZE == psa_cmd.signature_size, PSA_ERROR_INVALID_ARGUMENT,
                                         "Invalid blob CMAC size");

    psa_status = PSA_SUCCESS;
exit:
    return psa_status;
}

