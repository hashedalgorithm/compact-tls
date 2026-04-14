#include "ctls/types.h"
#include "tls.c"
#include "ctls/internal.h"
#include "psa/crypto.h"


ctls_op_status_t ctls_map_psa_error(psa_status_t status) {
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

ctls_op_status_t ctls_init_crypto(ctls_transcript_hash_t *transcript_hash) {
    psa_status_t result = psa_crypto_init();
    if (result != PSA_SUCCESS) return ctls_map_psa_error(result);

    transcript_hash->hash_operator = (psa_hash_operation_t)
            PSA_HASH_OPERATION_INIT;

    result = psa_hash_setup(&transcript_hash->hash_operator, PSA_ALG_SHA_256);

    return ctls_map_psa_error(result);
}

ctls_op_status_t ctls_calculate_transcript_hash(
    psa_hash_operation_t *hash_operator,
    uint8_t const *buffer, size_t const *offset) {
    psa_status_t const result = psa_hash_update(hash_operator, buffer, *offset);
    return ctls_map_psa_error(result);
}

ctls_op_status_t ctls_update_transcript_hash(ctls_record_t *record,
                                             ctls_profile_t *profile,
                                             psa_hash_operation_t *
                                             hash_operator) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(profile);
    CTLS_CHECK_NULL(hash_operator);

    uint8_t buffer[256];
    size_t offset = 0;

    switch (record->type) {
        case CTLS_RECORD_TYPE_CLIENT_HELLO: {
            tls_record_body_t tls_record_body;

            tls_build_record_client_hello(&tls_record_body, record, profile);
            tls_serialize_client_hello(&tls_record_body, buffer, &offset);
            break;
        }
        case CTLS_RECORD_TYPE_SERVER_HELLO: break;
        case CTLS_RECORD_TYPE_ENCRYPTED_EXTENSIONS: break;
        case CTLS_RECORD_TYPE_CERTIFICATE: break;
        case CTLS_RECORD_TYPE_CERTIFICATE_VERIFY: break;
        case CTLS_RECORD_TYPE_FINISHED: break;

        default: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
    }

    return ctls_calculate_transcript_hash(
        hash_operator, buffer, &offset);
}

ctls_op_status_t transcript_snapshot(psa_hash_operation_t *hash_operator,
                                     uint8_t *buffer) {
    psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;

    // copy internal SHA-256 state into clone — op is unaffected
    psa_status_t result = psa_hash_clone(hash_operator, &clone);
    if (result != PSA_SUCCESS) return ctls_map_psa_error(result);

    size_t out_len;

    // finish() on the clone: produces digest, destroys clone
    // op is still alive and accepting updates
    result = psa_hash_finish(&clone, buffer, CTLS_SIZE_TRANSCRIPT_HASH,
                             &out_len);
    return ctls_map_psa_error(result);
}


ctls_op_status_t ctls_generate_ephemeral_public_key(
    uint8_t *buffer, size_t buffer_length) {
    psa_key_id_t key_id;
    psa_key_attributes_t key_attributes =
            PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&key_attributes, 255);
    psa_set_key_usage_flags(&key_attributes,
                            PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
    psa_generate_key(&key_attributes, &key_id);


    psa_status_t const result = psa_export_public_key(key_id,
        buffer,
        CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE,
        &buffer_length);

    if (result != PSA_SUCCESS) return ctls_map_psa_error(result);

    return ctls_map_psa_error(PSA_SUCCESS);
}

ctls_op_status_t ctls_generate_random(uint8_t *buffer) {
    psa_status_t const result = psa_generate_random(
        buffer, CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM);
    return ctls_map_psa_error(result);
}


