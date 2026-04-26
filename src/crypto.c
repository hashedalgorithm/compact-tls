#include "ctls/types.h"
#include "ctls/ctls.h"
#include "psa/crypto.h"

#include "bytes.h"
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

ctls_op_status_t ctls_crypto_init(ctls_transcript_hash_t *transcript_hash) {
    psa_status_t result = psa_crypto_init();
    if (result != PSA_SUCCESS) return ctls_psa_error_map(result);

    transcript_hash->hash_operator = (psa_hash_operation_t) PSA_HASH_OPERATION_INIT;

    result = psa_hash_setup(&transcript_hash->hash_operator, PSA_ALG_SHA_256);

    return ctls_psa_error_map(result);
}

ctls_op_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                                uint8_t const *buffer,
                                                size_t const *offset) {
    psa_status_t const result = psa_hash_update(hash_operator, buffer, *offset);
    return ctls_psa_error_map(result);
}

ctls_op_status_t ctls_transcript_hash_update(ctls_record_t const *record,
                                             ctls_template_t const *template,
                                             psa_hash_operation_t *hash_operator) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hash_operator);

    uint8_t buffer[256];
    size_t offset = 0;

    // switch (record->type) {
    //     case CTLS_RECORD_TYPE_CLIENT_HELLO: {
    //         tls_record_body_t tls_record_body;
    //
    //         tls_build_record_client_hello(&tls_record_body, record, template);
    //         tls_serialize_client_hello(&tls_record_body, buffer, &offset);
    //         break;
    //     }
    //     case CTLS_RECORD_TYPE_SERVER_HELLO: break;
    //     case CTLS_RECORD_TYPE_ENCRYPTED_EXTENSIONS: break;
    //     case CTLS_RECORD_TYPE_CERTIFICATE: break;
    //     case CTLS_RECORD_TYPE_CERTIFICATE_VERIFY: break;
    //     case CTLS_RECORD_TYPE_FINISHED: break;
    //
    //     default: return (ctls_op_status_t){
    //             .source = CTLS_ERROR_SOURCE_INTERNAL,
    //             .code = CTLS_OP_STATUS_INVALID,
    //             .external_code = CTLS_OP_STATUS_INVALID,
    //         };
    // }

    return ctls_transcript_hash_calculate(hash_operator, buffer, &offset);
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


ctls_op_status_t ctls_ephemeral_public_key_generate(uint8_t *buffer,
                                                    ctls_size_t const buffer_length) {
    size_t buffer_length_st = buffer_length;

    psa_key_id_t key_id;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&key_attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&key_attributes, 255);
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
    psa_generate_key(&key_attributes, &key_id);


    psa_status_t const result = psa_export_public_key(key_id,
                                                      buffer,
                                                      CTLS_WIRE_KEY_SHARE,
                                                      &buffer_length_st);

    if (result != PSA_SUCCESS) return ctls_psa_error_map(result);

    return ctls_psa_error_map(PSA_SUCCESS);
}

ctls_op_status_t ctls_random_generate(uint8_t *buffer) {
    psa_status_t const result = psa_generate_random(buffer, CTLS_WIRE_RANDOM);
    return ctls_psa_error_map(result);
}

ctls_op_status_t ctls_handshake_message_serialize(ctls_handshake_message_t *message,
                                                  ctls_template_t const *template,
                                                  uint8_t *buffer) {
    CTLS_CHECK_NULL(message);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(buffer);

    /*
     * RFC 8446
     * struct {
     *    ProtocolVersion legacy_version;
     *    Random random;
     *    opaque legacy_session_id<0..32>;
     *    CipherSuite cipher_suites<2..2^16-2>;
     *    opaque legacy_compression_methods<1..2^8-1>;
     *    Extension extensions<8..2^16-1>;
     * } ClientHello;
    */

    ctls_size_t offset = 0;

    ctls_write_u8(buffer, &offset, message->message_type);

    ctls_size_t body_start = offset;
    offset += 3;

    ctls_write_u16(buffer,
                   &offset,
                   message->handshake_message_body.client_hello.protocol_version);
    ctls_write_bytes(buffer,
                     &offset,
                     CTLS_WIRE_RANDOM,
                     message->handshake_message_body.client_hello.random.buffer);

    ctls_write_u8(buffer, &offset, 0x01);
    ctls_write_u8(buffer,
                  &offset,
                  message->handshake_message_body.client_hello.legacy_session_id);
    ctls_write_u16(buffer, &offset, 0x01);
    ctls_write_u16(buffer,
                   &offset,
                   message->handshake_message_body.client_hello.cipher_suite);


    // uint8 legacy_compression_method = 0;
    ctls_write_u8(buffer, &offset, 0x01);
    ctls_write_u8(buffer, &offset, 0x00);

    // Extension extensions<8..2^16-1>;
    ctls_size_t extenstions_start = offset;
    offset += 2;

    // ctls_write_u16(buffer, &offset, )
}
