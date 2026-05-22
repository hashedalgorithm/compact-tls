#include "ctls/types.h"
#include "ctls/ctls.h"
#include "psa/crypto.h"
#include "ctls/bytes.h"
#include "ctls/templates.h"


ctls_op_status_t ctls_psa_error_map(psa_status_t const status) {
    switch (status) {
        case PSA_SUCCESS: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_SUCCESS,
                .external_code = PSA_SUCCESS,
            };
        case PSA_ERROR_INVALID_SIGNATURE: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = PSA_ERROR_INVALID_SIGNATURE,
            };
        case PSA_ERROR_BUFFER_TOO_SMALL: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_OVERFLOW,
                .external_code = PSA_ERROR_BUFFER_TOO_SMALL,
            };
        case PSA_ERROR_INVALID_ARGUMENT: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = PSA_ERROR_INVALID_ARGUMENT,
            };
        case PSA_ERROR_NOT_SUPPORTED: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_ERROR,
                .external_code = PSA_ERROR_NOT_SUPPORTED,
            };
        case PSA_ERROR_INSUFFICIENT_ENTROPY: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_ERROR,
                .external_code = PSA_ERROR_INSUFFICIENT_ENTROPY,
            };
        default: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_CRYPTO,
                .code = CTLS_OP_STATUS_ERROR,
                .external_code = (uint16_t) status,
            };
    }
}

ctls_op_status_t ctls_crypto_init() {
    ctls_template_t const *template = ctls_template_get();
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hshk_data);

    psa_status_t psa_result = psa_crypto_init();
    if (psa_result != PSA_SUCCESS) return ctls_psa_error_map(psa_result);

    ctls_op_status_t result = ctls_psa_hash_algorithm_set(crypto, template->cipher_suite);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    result = ctls_transcript_hash_init(crypto, hshk_data->transcript_hash, template);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_hkdf_init(crypto, template->dhe_group.dhe_group);
}

ctls_op_status_t ctls_psa_hash_algorithm_set(ctls_crypto_t *crypto,
                                             ctls_hsmg_cipher_suite_type_t const
                                             cipher_suite) {
    switch (cipher_suite) {
        case CTLS_HSMG_CIPHER_SUITE_AES_128_GCM_SHA256:
        case CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_8_SHA256:
        case CTLS_HSMG_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        case CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_SHA256:
            crypto->hash_algorithm = PSA_ALG_SHA_256;
            break;
        case CTLS_HSMG_CIPHER_SUITE_AES_256_GCM_SHA384:
            crypto->hash_algorithm = PSA_ALG_SHA_384;
            break;
        default: return ctls_psa_error_map(PSA_ERROR_INVALID_ARGUMENT);
    }
    return ctls_psa_error_map(PSA_SUCCESS);
}

ctls_op_status_t ctls_psa_ecc_family_set(ctls_crypto_t *crypto,
                                         ctls_extn_dhe_group_type_t const
                                         dhe_group_type) {
    switch (dhe_group_type) {
        case CTLS_EXTN_DHE_GROUP_FFDHE2048:
        case CTLS_EXTN_DHE_GROUP_FFDHE4096:
        case CTLS_EXTN_DHE_GROUP_FFDHE3072:
            crypto->ecdhe_key_pair_type = PSA_DH_FAMILY_RFC7919;
            break;
        case CTLS_EXTN_DHE_GROUP_SECP256R1:
        case CTLS_EXTN_DHE_GROUP_SECP384R1:
        case CTLS_EXTN_DHE_GROUP_SECP521R1:
            crypto->ecdhe_key_pair_type = PSA_ECC_FAMILY_SECP_R1;
            break;
        case CTLS_EXTN_DHE_GROUP_X448:
        case CTLS_EXTN_DHE_GROUP_X25519:
            crypto->ecdhe_key_pair_type = PSA_ECC_FAMILY_MONTGOMERY;
            break;
        default: return ctls_psa_error_map(PSA_ERROR_INVALID_ARGUMENT);
    }
    return ctls_psa_error_map(PSA_SUCCESS);
}

ctls_op_status_t ctls_transcript_hash_init(ctls_crypto_t *crypto,
                                           uint8_t *transcript_hash,
                                           ctls_template_t const *template) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(template);

    crypto->transcript_hash_operator = (psa_hash_operation_t) PSA_HASH_OPERATION_INIT;

    psa_status_t const result = psa_hash_setup(&crypto->transcript_hash_operator,
                                               crypto->hash_algorithm);
    if (result != PSA_SUCCESS) return ctls_psa_error_map(result);


    ctls_op_status_t const res = ctls_template_to_wire(transcript_hash);
    if (res.code != CTLS_OP_STATUS_SUCCESS) return res;

    return ctls_transcript_hash_calculate(&crypto->transcript_hash_operator,
                                          transcript_hash);
}

ctls_op_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                                uint8_t *transcript_hash) {
    CTLS_CHECK_NULL(hash_operator);
    CTLS_CHECK_NULL(transcript_hash);

    psa_status_t const result = psa_hash_update(hash_operator,
                                                transcript_hash,
                                                CTLS_SIZE_TRANSCRIPT_HASH);

    return ctls_psa_error_map(result);
}

ctls_op_status_t ctls_transcript_hash_update(ctls_record_t const *record) {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);


    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t offset = 0;

    switch (record->record_body.message_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO: {
            ctls_recd_client_hello_to_wire(buffer,
                                           &offset,
                                           CTLS_SIZE_WIRE_BUFFER,
                                           record,
                                           CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);

            break;
        }
        case CTLS_HSMG_TYPE_SERVER_HELLO: {
            ctls_recd_server_hello_to_wire(buffer,
                                           &offset,
                                           CTLS_SIZE_WIRE_BUFFER,
                                           record,
                                           CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        }
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS: {
            ctls_recd_encrypted_extensions_to_wire(buffer,
                                                   &offset,
                                                   record,
                                                   CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        }
        case CTLS_HSMG_TYPE_CERTIFICATE: {
            ctls_recd_certificate_request_to_wire(buffer,
                                                  &offset,
                                                  record,
                                                  CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        }
        case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY: {
            ctls_recd_certificate_verify_to_wire();
            break;
        }
        case CTLS_HSMG_TYPE_FINISHED: {
            ctls_recd_finished_to_wire();
            break;
        }
        case CTLS_HSMG_TYPE_NEW_SESSION_TICKET:
        case CTLS_HSMG_TYPE_END_OF_EARLY_DATA:
        case CTLS_HSMG_TYPE_HELLO_RETRY_REQUEST:
        case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
        case CTLS_HSMG_TYPE_KEY_UPDATE:
        case CTLS_HSMG_TYPE_MESSAGE_HASH:
        case CTLS_HSMG_TYPE_SENTINEL: default: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
    }

    return ctls_transcript_hash_calculate(&crypto->transcript_hash_operator,
                                          hshk_data->transcript_hash);
}

ctls_op_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                     uint8_t *buffer) {
    psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;

    // copy internal SHA-256 state into clone — op is unaffected
    psa_status_t result = psa_hash_clone(hash_operator, &clone);
    if (result != PSA_SUCCESS) return ctls_psa_error_map(result);

    size_t out_len;

    // finish() on the clone: produces digest, destroys clone
    // op is still alive and accepting updates
    result = psa_hash_finish(&clone, buffer, CTLS_SIZE_TRANSCRIPT_HASH, &out_len);
    return ctls_psa_error_map(result);
}

ctls_op_status_t ctls_hkdf_init(ctls_crypto_t *crypto,
                                ctls_extn_dhe_group_type_t const ecdhe_group_type) {
    CTLS_CHECK_NULL(crypto);

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_psa_ecc_family_set(crypto, ecdhe_group_type);
}

ctls_op_status_t ctls_key_schedule_operator_reset(ctls_crypto_t *crypto) {
    CTLS_CHECK_NULL(crypto);

    crypto->key_schedule_operator = (psa_key_derivation_operation_t)
            PSA_KEY_DERIVATION_OPERATION_INIT;
    return ctls_psa_error_map(PSA_SUCCESS);
}

ctls_op_status_t ctls_ephemeral_public_key_generate(uint8_t *buffer,
                                                    ctls_size_t *bytes_written) {
    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(crypto);

    size_t bytes_written_st = *bytes_written;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;


    psa_set_key_type(&key_attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(crypto->ecdhe_key_pair_type));
    psa_set_key_bits(&key_attributes, 255);
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
    psa_generate_key(&key_attributes, &crypto->client_private_ephemeral_key_id);


    psa_status_t const result =
            psa_export_public_key(crypto->client_private_ephemeral_key_id,
                                  buffer,
                                  CTLS_SIZE_KEY_SHARE,
                                  &bytes_written_st);

    *bytes_written = (ctls_size_t) bytes_written_st;

    if (result != PSA_SUCCESS) return ctls_psa_error_map(result);

    return ctls_psa_error_map(PSA_SUCCESS);
}

ctls_op_status_t ctls_random_generate(uint8_t *buffer,
                                      ctls_size_t *bytes_written,
                                      uint8_t const random_size) {
    psa_status_t const result = psa_generate_random(buffer, random_size);

    *bytes_written = random_size;
    return ctls_psa_error_map(result);
}

ctls_op_status_t ctls_key_schedule() {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_op_status_t result = ctls_early_secret_generate(crypto, hshk_data->early_secret);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    result = ctls_derived_secret_generate(crypto, hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    result = ctls_shared_ephemeral_secret_generate(crypto, hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    result = ctls_handshake_secret_generate(crypto, hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    result = ctls_handshake_traffic_secrets_generate(crypto, hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    result = ctls_handshake_keys_generate(crypto, hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_handshake_iv_keys_generate(crypto, hshk_data);
}


ctls_op_status_t ctls_early_secret_generate(ctls_crypto_t *crypto,
                                            uint8_t *early_secret) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(early_secret);

    static const uint8_t ZEROS[32] = {0};

    psa_status_t psa_st = PSA_ERROR_DOES_NOT_EXIST;

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t ikm_key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXTRACT(crypto->hash_algorithm));
    psa_set_key_bits(&attr, 256U);

    psa_st = psa_import_key(&attr, ZEROS, CTLS_SIZE_HASH, &ikm_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXTRACT(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            ZEROS,
                                            CTLS_SIZE_HASH);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          ikm_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             early_secret,
                                             CTLS_SIZE_HASH);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return ctls_psa_error_map(psa_st);
cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (ikm_key != PSA_KEY_ID_NULL) { psa_destroy_key(ikm_key); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}


ctls_op_status_t ctls_derived_secret_generate(ctls_crypto_t *crypto,
                                              ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    /* derived_secret = HKDF-Expand-Label(early_secret, "derived", H(""), 32)
     *
     * H("") = SHA-256 of empty string (fixed constant)
     * Label prefix: "Sctls " (cTLS draft-10 §6)
     *
     * HkdfLabel encoding:
     *   uint16 length       = 32
     *   uint8  label_len    = len("Sctls derived")
     *   bytes  label        = "Sctls derived"
     *   uint8  context_len  = 32
     *   bytes  context      = H("")
     */

    /* Build HkdfLabel info block */
    static const char LABEL[] = "Sctls derived";
    static const uint8_t LABEL_LENGTH = sizeof(LABEL) - 1U;

    uint8_t info[2U + 1U + sizeof(LABEL) - 1U + 1U + 32U];
    ctls_size_t offset = 0U;

    ctls_write_u16(info, &offset, 0x00);
    ctls_write_u8(info, &offset, 0x20);
    ctls_write_u8(info, &offset, LABEL_LENGTH);
    ctls_write_bytes(info, &offset, LABEL_LENGTH, LABEL);
    ctls_write_u8(info, &offset, 0x20);
    ctls_write_bytes(info, &offset, 32U, hshk_data->transcript_hash);


    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    psa_set_key_bits(&attr, 256U);

    psa_st = psa_import_key(&attr, hshk_data->early_secret, 32U, &prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;


    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;


    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info,
                                            offset);
    if (psa_st != PSA_SUCCESS) goto cleanup;


    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->derived_secret,
                                             32U);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return ctls_psa_error_map(CTLS_OP_STATUS_SUCCESS);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (prk_key != PSA_KEY_ID_NULL) { psa_destroy_key(prk_key); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}


ctls_op_status_t ctls_shared_ephemeral_secret_generate(ctls_crypto_t const *crypto,
                                                       ctls_hshk_data_t *hshk_data) {
    psa_status_t psa_st = PSA_SUCCESS;

    size_t shared_ephemeral_secret_length = 0;

    psa_st = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   crypto->client_private_ephemeral_key_id,
                                   hshk_data->server_public_ephemeral_key,
                                   CTLS_SIZE_KEY_SHARE,
                                   hshk_data->shared_ephemeral_secret,
                                   CTLS_SIZE_KEY_SHARE,
                                   &shared_ephemeral_secret_length);

    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_handshake_secret_generate(ctls_crypto_t *crypto,
                                                ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t ikm_key = PSA_KEY_ID_NULL;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    /* Import Z as IKM into PSA key storage */
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXTRACT(crypto->hash_algorithm));
    psa_set_key_bits(&attr, CTLS_SIZE_KEY_SHARE * 8U);

    psa_st = psa_import_key(&attr,
                            hshk_data->shared_ephemeral_secret,
                            CTLS_SIZE_KEY_SHARE,
                            &ikm_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;


    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXTRACT(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;


    /* Salt = derived_secret from previous step */
    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            hshk_data->derived_secret,
                                            32U);
    if (psa_st != PSA_SUCCESS) goto cleanup;


    /* IKM = Z */
    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          ikm_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;


    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->handshake_secret,
                                             32U);
    if (psa_st != PSA_SUCCESS) goto cleanup;


    return ctls_psa_error_map(psa_st);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (ikm_key != PSA_KEY_ID_NULL) { psa_destroy_key(ikm_key); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_handshake_traffic_secrets_generate(
    ctls_crypto_t *crypto,
    ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_op_status_t result =
            ctls_client_handshake_traffic_secret_generate(crypto, hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_server_handshake_traffic_secret_generate(crypto, hshk_data);
}

ctls_op_status_t ctls_client_handshake_traffic_secret_generate(
    ctls_crypto_t *crypto,
    ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    /* client_hs_traffic = HKDF-Expand-Label(handshake_secret, "c hs traffic", H(CH..SH), 32)
     * server_hs_traffic = HKDF-Expand-Label(handshake_secret, "s hs traffic", H(CH..SH), 32)
     *
     * HkdfLabel:
     *   uint16 length      = 32
     *   uint8  label_len
     *   bytes  label       = "Sctls " + label
     *   uint8  context_len = 32
     *   bytes  context     = transcript_hash
     */

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    psa_set_key_bits(&attr, 256U);

    psa_st = psa_import_key(&attr, hshk_data->handshake_secret, 32U, &prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    static const char CLIENT_LABEL[] = "Sctls c hs traffic";
    static const uint8_t CLIENT_LABEL_LEN = sizeof(CLIENT_LABEL) - 1U;

    uint8_t client_info[2U + 1U + 1U + 1U + CTLS_SIZE_TRANSCRIPT_HASH];
    ctls_size_t client_info_offset = 0U;

    ctls_write_u16(client_info, &client_info_offset, 0x00);
    ctls_write_u8(client_info, &client_info_offset, 0x20);
    ctls_write_u8(client_info, &client_info_offset, sizeof(CLIENT_LABEL) - 1U);
    ctls_write_bytes(client_info, &client_info_offset, CLIENT_LABEL_LEN, CLIENT_LABEL);
    ctls_write_u8(client_info, &client_info_offset, CTLS_SIZE_HASH);
    ctls_write_bytes(client_info,
                     &client_info_offset,
                     CTLS_SIZE_HASH,
                     hshk_data->transcript_hash);


    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            client_info,
                                            client_info_offset);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->client_handshake_traffic_secret,
                                             32U);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return ctls_psa_error_map(psa_st);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (prk_key != PSA_KEY_ID_NULL) { psa_destroy_key(prk_key); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_server_handshake_traffic_secret_generate(ctls_crypto_t *crypto,
    ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    psa_set_key_bits(&attr, 256U);

    static const uint8_t SERVER_LABEL[] = "Sctls s hs traffic";
    static const uint8_t SERVER_LABEL_LENGTH = sizeof(SERVER_LABEL) - 1U;

    uint8_t server_info[2U + 1U + 1U + 1U + CTLS_SIZE_TRANSCRIPT_HASH];
    ctls_size_t server_info_offset = 0U;

    ctls_write_u16(server_info, &server_info_offset, 0x00);
    ctls_write_u8(server_info, &server_info_offset, 0x20);
    ctls_write_u8(server_info, &server_info_offset, sizeof(SERVER_LABEL) - 1U);
    ctls_write_bytes(server_info, &server_info_offset, SERVER_LABEL_LENGTH, SERVER_LABEL);
    ctls_write_u8(server_info, &server_info_offset, CTLS_SIZE_HASH);
    ctls_write_bytes(server_info,
                     &server_info_offset,
                     CTLS_SIZE_HASH,
                     hshk_data->transcript_hash);

    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            server_info,
                                            server_info_offset);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->server_handshake_traffic_secret,
                                             32U);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    return ctls_psa_error_map(psa_st);
cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}


ctls_op_status_t ctls_handshake_key_generate(ctls_crypto_t *crypto,
                                             ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    /*  Handshake_key = HKDF-Expand-Label(traffic_secret, "key", "", 16)
    *   HkdfLabel for key:
    *   uint16 length      = 16
    *   uint8  label_len   = len("Sctls key")
    *   bytes  label       = "Sctls key"
    *   uint8  context_len = 0    (empty context)
    */
    static const uint8_t HANDSHAKE_KEY_LABEL[] = "Sctls key";
    static const uint8_t HANDSHAKE_KEY_LABEL_LENGTH = sizeof(HANDSHAKE_KEY_LABEL) - 1U;

    uint8_t handshake_key_info[2U + 1U + 1U + 1U];
    ctls_size_t handshake_key_info_offset = 0U;

    ctls_write_u16(handshake_key_info, &handshake_key_info_offset, 0x00);
    ctls_write_u8(handshake_key_info, &handshake_key_info_offset, 0x10); /* length = 16 */
    ctls_write_u8(handshake_key_info,
                  &handshake_key_info_offset,
                  sizeof(HANDSHAKE_KEY_LABEL) - 1U);
    ctls_write_bytes(handshake_key_info,
                     &handshake_key_info_offset,
                     HANDSHAKE_KEY_LABEL_LENGTH,
                     HANDSHAKE_KEY_LABEL);
    /* context_len = 0 */
    ctls_write_u8(handshake_key_info, &handshake_key_info_offset, 0x00);

    ctls_op_status_t const result = ctls_client_handshake_key_generate(crypto,
        hshk_data,
        handshake_key_info,
        &handshake_key_info_offset);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;
    return ctls_server_handshake_key_generate(crypto,
                                              hshk_data,
                                              handshake_key_info,
                                              &handshake_key_info_offset);
}

ctls_op_status_t ctls_client_handshake_key_generate(ctls_crypto_t *crypto,
                                                    ctls_hshk_data_t *hshk_data,
                                                    uint8_t const *handshake_key_info,
                                                    ctls_size_t const *
                                                    handshake_key_info_offset) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);


    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;
    size_t const handshake_key_info_offset_s = *handshake_key_info_offset;

    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    psa_set_key_bits(&attr, 256U);

    psa_st = psa_import_key(&attr,
                            hshk_data->client_handshake_traffic_secret,
                            32U,
                            &prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    /* client write key */
    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            handshake_key_info,
                                            handshake_key_info_offset_s);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->client_handshake_key,
                                             16U);
    if (psa_st != PSA_SUCCESS) goto cleanup;
    return ctls_psa_error_map(psa_st);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (prk_key != PSA_KEY_ID_NULL) { psa_destroy_key(prk_key); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_server_handshake_key_generate(ctls_crypto_t *crypto,
                                                    ctls_hshk_data_t *hshk_data,
                                                    uint8_t const *handshake_key_info,
                                                    ctls_size_t const *
                                                    handshake_key_info_offset) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;
    size_t const handshake_key_info_offset_s = *handshake_key_info_offset;
    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;


    psa_st = psa_import_key(&attr,
                            hshk_data->server_handshake_traffic_secret,
                            32U,
                            &prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    /* server write key */
    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            handshake_key_info,
                                            handshake_key_info_offset_s);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->server_handshake_key,
                                             16U);
    if (psa_st != PSA_SUCCESS) goto cleanup;
    return ctls_psa_error_map(psa_st);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    if (prk_key != PSA_KEY_ID_NULL) { psa_destroy_key(prk_key); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_handshake_iv_keys_generate(ctls_crypto_t *crypto,
                                                 ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    /* write_iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", 12)
    * HkdfLabel for iv:
    *   uint16 length      = 12
    *   uint8  label_len   = len("Sctls iv")
    *   bytes  label       = "Sctls iv"
    *   uint8  context_len = 0    (empty context)
    */

    static const uint8_t IV_KEY_LABEL[] = "Sctls iv";
    static const uint8_t IV_KEY_LABEL_LENGTH = sizeof(IV_KEY_LABEL) - 1U;

    uint8_t iv_key_info[2U + 1U + 1U + 1U];
    ctls_size_t iv_key_info_offset = 0U;

    ctls_write_u16(iv_key_info, &iv_key_info_offset, 0x00);
    ctls_write_u8(iv_key_info, &iv_key_info_offset, 0x0C); /* length = 16 */
    ctls_write_u8(iv_key_info, &iv_key_info_offset, sizeof(IV_KEY_LABEL) - 1U);
    ctls_write_bytes(iv_key_info, &iv_key_info_offset, IV_KEY_LABEL_LENGTH, IV_KEY_LABEL);
    /* context_len = 0 */
    ctls_write_u8(iv_key_info, &iv_key_info_offset, 0x00);

    ctls_op_status_t const result = ctls_client_handshake_iv_key_generate(crypto,
        hshk_data,
        iv_key_info,
        &iv_key_info_offset);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;
    return ctls_server_handshake_iv_key_generate(crypto,
                                                 hshk_data,
                                                 iv_key_info,
                                                 &iv_key_info_offset);
}

ctls_op_status_t ctls_client_handshake_iv_key_generate(ctls_crypto_t *crypto,
                                                       ctls_hshk_data_t *hshk_data,
                                                       uint8_t const *iv_key_info,
                                                       ctls_size_t const *
                                                       iv_key_info_offset) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);
    /* write_iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", 12)
    * HkdfLabel for iv:
    *   uint16 length      = 12
    *   uint8  label_len   = len("Sctls iv")
    *   bytes  label       = "Sctls iv"
    *   uint8  context_len = 0    (empty context)
    */
    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;
    size_t const iv_key_info_offset_s = *iv_key_info_offset;
    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;


    /* client write iv */
    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            iv_key_info,
                                            iv_key_info_offset_s);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->client_handshake_iv_key,
                                             CTLS_SIZE_IV);
    if (psa_st != PSA_SUCCESS) goto cleanup;
    return ctls_psa_error_map(psa_st);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_server_handshake_iv_key_generate(ctls_crypto_t *crypto,
                                                       ctls_hshk_data_t *hshk_data,
                                                       uint8_t const *iv_key_info,
                                                       ctls_size_t const *
                                                       iv_key_info_offset) {
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    /* write_iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", 12)
    * HkdfLabel for iv:
    *   uint16 length      = 12
    *   uint8  label_len   = len("Sctls iv")
    *   bytes  label       = "Sctls iv"
    *   uint8  context_len = 0    (empty context)
    */
    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_key = PSA_KEY_ID_NULL;
    size_t const iv_key_info_offset_s = *iv_key_info_offset;
    ctls_op_status_t const result = ctls_key_schedule_operator_reset(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    /* server write iv */
    psa_st = psa_key_derivation_setup(&crypto->key_schedule_operator,
                                      PSA_ALG_HKDF_EXPAND(crypto->hash_algorithm));
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_key(&crypto->key_schedule_operator,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk_key);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_input_bytes(&crypto->key_schedule_operator,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            iv_key_info,
                                            iv_key_info_offset_s);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_key_derivation_output_bytes(&crypto->key_schedule_operator,
                                             hshk_data->server_handshake_iv_key,
                                             CTLS_SIZE_IV);
    if (psa_st != PSA_SUCCESS) goto cleanup;
    return ctls_psa_error_map(psa_st);

cleanup:
    psa_key_derivation_abort(&crypto->key_schedule_operator);
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}

ctls_op_status_t ctls_nonce_generate(uint8_t *buffer,
                                     uint16_t const *sequence_number,
                                     uint8_t const *iv_key) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(iv_key);
    CTLS_CHECK_NULL(sequence_number);

    ctls_write_bytes(buffer, 0, CTLS_SIZE_NONCE, iv_key);
    for (int i = 0; i < 8; i++) {
        buffer[11 - i] ^= (uint8_t) (*sequence_number >> (i * 8U));
    }
}

ctls_op_status_t ctls_decrypt(uint16_t const *sequence_number,
                              /* sequence number, starts at 0, increments per record */
                              uint8_t const *aad,
                              /* additional authenticated data (record header bytes) */
                              size_t aad_len,
                              const uint8_t *ciphertext,
                              /* encrypted bytes */
                              size_t ciphertext_len,
                              uint8_t *buffer,
                              /* caller-allocated, at least ciphertext_len - 16 bytes */
                              size_t *bytes_written) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    uint8_t *handshake_key;
    uint8_t *iv_key;

    if (CTLS_CLIENT) {
        CTLS_CHECK_NULL(hshk_data->client_handshake_key);
        CTLS_CHECK_NULL(hshk_data->client_handshake_iv_key);

        handshake_key = hshk_data->client_handshake_key;
        iv_key = hshk_data->client_handshake_iv_key;
    }

    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL(sequence_number);
    CTLS_CHECK_NULL(aad);
    CTLS_CHECK_NULL(ciphertext);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(bytes_written);

    psa_status_t psa_st = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    /* Build per-record nonce */
    uint8_t nonce[CTLS_SIZE_NONCE];
    ctls_op_status_t result = ctls_nonce_generate(nonce, sequence_number, iv_key);
    if (result.code != CTLS_OP_STATUS_SUCCESS) goto cleanup;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_bits(&attr, 128U);

    psa_st = psa_import_key(&attr, handshake_key, 16U, &key_id);
    if (psa_st != PSA_SUCCESS) goto cleanup;

    psa_st = psa_aead_decrypt(key_id,
                              PSA_ALG_GCM,
                              nonce,
                              CTLS_SIZE_NONCE,
                              aad,
                              aad_len,
                              ciphertext,
                              ciphertext_len,
                              buffer,
                              ciphertext_len - 16U,
                              bytes_written);
    if (psa_st != PSA_SUCCESS) goto cleanup;
    return ctls_psa_error_map(psa_st);


cleanup:
    if (key_id != PSA_KEY_ID_NULL) { psa_destroy_key(key_id); }
    psa_reset_key_attributes(&attr);
    return ctls_psa_error_map(psa_st);
}
