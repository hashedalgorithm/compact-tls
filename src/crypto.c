#include "ctls/types.h"
#include "ctls/ctls.h"
#include "psa/crypto.h"

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

ctls_op_status_t ctls_crypto_init(ctls_crypto_t *crypto,
                                  ctls_template_t const *template,
                                  ctls_hshk_data_t *hshk_data) {
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


    ctls_op_status_t const res = ctls_template_to_wire(transcript_hash, template);
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

ctls_op_status_t ctls_transcript_hash_update(ctls_record_t const *record,
                                             ctls_template_t const *template,
                                             psa_hash_operation_t *hash_operator,
                                             uint8_t *transcript_hash) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hash_operator);

    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t offset = 0;

    switch (record->record_body.message_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO: {
            ctls_recd_client_hello_to_wire(buffer,
                                           &offset,
                                           CTLS_SIZE_WIRE_BUFFER,
                                           record,
                                           template,
                                           CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);

            break;
        }
        case CTLS_HSMG_TYPE_SERVER_HELLO: {
            ctls_recd_server_hello_to_wire(buffer,
                                           &offset,
                                           CTLS_SIZE_WIRE_BUFFER,
                                           record,
                                           template,
                                           CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            break;
        }
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS: {
            ctls_recd_encrypted_extensions_to_wire();
            break;
        }
        case CTLS_HSMG_TYPE_CERTIFICATE: {
            ctls_recd_certificate_to_wire();
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

    return ctls_transcript_hash_calculate(hash_operator, transcript_hash);
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

    ctls_op_status_t const result = ctls_psa_attribute_init(crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_psa_ecc_family_set(crypto, ecdhe_group_type);
}


ctls_op_status_t ctls_ephemeral_public_key_generate(uint8_t *buffer,
                                                    ctls_size_t *bytes_written,
                                                    ctls_crypto_t *crypto) {
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
                                      const uint8_t random_size) {
    psa_status_t const result = psa_generate_random(buffer, random_size);

    *bytes_written = random_size;
    return ctls_psa_error_map(result);
}

