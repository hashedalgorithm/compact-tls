#include "ctls/ctls.h"

#include <stdbool.h>
#include "ctls/internal.h"
#include "crypto.c"

ctls_op_status_t ctls_build_unified_header(
    const ctls_recd_config_octet_t *config,
    uint16_t sequence_number,
    uint16_t length,
    uint8_t *buffer,
    size_t *buffer_length) {
    CTLS_CHECK_NULL(config);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);

    size_t offset = 0;

    /* ---- config octet ---- */
    /* fixed bits 7-5 = 0b001, per RFC 9147 §4 */
    uint8_t octet = CTLS_RECD_CONFIG_OCTET_FIXED_VALUE;

    /* C bit (4): CID present */
    if (config->c_bit)
        octet |= CTLS_RECD_CONFIG_OCTET_C_MASK;

    /* S bit (3): sequence number length — 0=8bit, 1=16bit */
    if (config->s_bit)
        octet |= CTLS_RECD_CONFIG_OCTET_S_MASK;

    /* L bit (2): length field present */
    if (config->l_bit)
        octet |= CTLS_RECD_CONFIG_OCTET_L_MASK;

    /* E bits (1-0): low 2 bits of epoch */
    octet |= (config->epoch & CTLS_RECD_CONFIG_OCTET_EPOCH_MASK);

    buffer[offset++] = octet;

    /* ---- connection ID ---- */
    /* C bit is 0 in your LoRaWAN setup — CID field omitted entirely.
     * When CID support is added, write CID bytes here.             */

    /* ---- sequence number ---- */
    /* cTLS-10 §2.2: on reliable ordered transport (LoRaWAN),
     * S bit MUST be cleared and sequence number MUST be omitted.
     * Written here only when S=1 (unreliable transport).           */
    if (config->s_bit) {
        if (octet & CTLS_RECD_CONFIG_OCTET_S_MASK) {
            /* S=1: 16-bit sequence number */
            ctls_write_u16(buffer, &offset, sequence_number);
        } else {
            /* S=0: 8-bit sequence number */
            buffer[offset++] = sequence_number & 0xFF;
        }
    }

    /* ---- length ---- */
    /* cTLS-10 §2.2: on stream transport, L MUST be 1.
     * On datagram transport L may be 0 (length inferred from UDP). */
    if (config->l_bit) {
        ctls_write_u16(buffer, &offset, length);
    }

    *buffer_length = offset;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t ctls_record_serialize(ctls_record_t *record,
                                       uint8_t *buffer,
                                       size_t const buffer_size,
                                       size_t *buffer_length) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);

    size_t offset = 0;

    // header: content_type (1 byte)
    if (offset + CTLS_WIRE_CONTENT_TYPE > buffer_size)
        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_OVERFLOW,
            .external_code = CTLS_OP_STATUS_OVERFLOW,
        };

    buffer[offset++] = record->header.content_type;

    // header: sequence_number (8 bytes, big-endian)
    if (offset + CTLS_WIRE_SEQUENCE_NUMBER > buffer_size)
        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_OVERFLOW,
            .external_code = CTLS_OP_STATUS_OVERFLOW,
        };
    ctls_write_u64(buffer, &offset, record->header.sequence_number);


    // header: length (2 bytes, big-endian) — placeholder, filled after body
    if (offset + CTLS_WIRE_LENGTH > buffer_size)
        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_OVERFLOW,
            .external_code = CTLS_OP_STATUS_OVERFLOW,
        };
    size_t length_offset = offset;
    buffer[offset++] = 0;
    buffer[offset++] = 0;

    // body — depends on record type
    const size_t body_start = offset;

    switch (record->type) {
        case CTLS_RECORD_TYPE_CLIENT_HELLO: {
            const ctls_record_body_client_hello_t *client_hello = &record->body.
                    client_hello;

            if (offset + CTLS_WIRE_PROFILE_ID >
                buffer_size)
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_OVERFLOW,
                    .external_code = CTLS_OP_STATUS_OVERFLOW,
                };
            ctls_write_u16(buffer, &offset, client_hello->profile_id);

            if (offset + CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM >
                buffer_size)
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_OVERFLOW,
                    .external_code = CTLS_OP_STATUS_OVERFLOW,
                };
            memcpy(buffer + offset, client_hello->random,
                   CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM);
            offset += CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM;

            if (offset + CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE >
                buffer_size)
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_OVERFLOW,
                    .external_code = CTLS_OP_STATUS_OVERFLOW,
                };
            memcpy(buffer + offset, client_hello->key_share,
                   CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE);
            offset += CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE;
            break;
        }
        case CTLS_RECORD_TYPE_SERVER_HELLO: {
        }
        case CTLS_RECORD_TYPE_ENCRYPTED_EXTENSIONS: {
        }
        case CTLS_RECORD_TYPE_CERTIFICATE: {
        }
        case CTLS_RECORD_TYPE_CERTIFICATE_VERIFY: {
        }
        case CTLS_RECORD_TYPE_FINISHED: {
        }
        default:
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
    }

    // fill in body length
    const uint16_t body_length = (uint16_t) (offset - body_start);
    ctls_write_u16(buffer, &length_offset, body_length);

    *buffer_length = offset;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_record_deserialize(ctls_record_t *record,
                                         uint8_t *buffer,
                                         size_t const buffer_length) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_BOUNDS(0, CTLS_WIRE_SIZE_RECORD_HEADER, buffer_length);

    size_t offset = 0;

    // header
    record->header.content_type = ctls_read_u8(buffer, &offset);
    record->header.sequence_number = ctls_read_u64(buffer, &offset);
    record->header.length = ctls_read_u16(buffer, &offset);

    CTLS_CHECK_BOUNDS(offset, record->header.length, buffer_length);

    // body
    switch (record->header.content_type) {
        case CTLS_CONTENT_TYPE_HANDSHAKE: {
            record->type = CTLS_RECORD_TYPE_SERVER_HELLO;
            ctls_record_body_server_hello_t *server_hello = &record->body.
                    server_hello;
            CTLS_CHECK_BOUNDS(
                offset,
                CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM +
                CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE,
                buffer_length);
            ctls_read_bytes(server_hello->random,
                            CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM, buffer,
                            &offset);
            ctls_read_bytes(server_hello->key_share,
                            CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE,
                            buffer, &offset);
            break;
        }
        case CTLS_CONTENT_TYPE_APPLICATION_DATA: {
        }
        case CTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: {
        }
        case CTLS_CONTENT_TYPE_ALERT: {
        }
        case CTLS_CONTENT_TYPE_HEARTBEAT: {
        }
        default:
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_clear_record_buffer(
    ctls_record_t *record_buffer) {
    memset(record_buffer, 0, sizeof(ctls_record_t));

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_validate_profile(
    const ctls_profile_t *profile) {
    CTLS_CHECK_NULL(profile);

    if (profile->cipher_suite == 0 ||
        profile->dhe_group == 0 ||
        profile->signature_algorithm == 0)
        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_INVALID,
            .external_code = CTLS_OP_STATUS_INVALID,
        };

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_context_init(ctls_context_t *context,
                                   const ctls_transport_t *transport) {
    ctls_init_crypto(&context->transcript_hash);
    memset(context, 0, sizeof(ctls_context_t));

    context->transport = *transport;

    context->state = CTLS_HSHK_STATE_START;

    context->profile.version = CTLS_HSMG_VERSION_1_3;
    context->profile.profile_id = CTLS_PROFILE_ID;
    context->profile.dhe_group = CTLS_DHE_GROUP;
    context->profile.cipher_suite = CTLS_CIPHER_SUIT;
    context->profile.signature_algorithm = CTLS_SIGNATURE_ALGORITHM;

    return ctls_validate_profile(&context->profile);
}

ctls_op_status_t ctls_connect(ctls_context_t *context) {
    ctls_op_status_t const result = ctls_validate_profile(
        &context->profile);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_handshake(context);
}


ctls_op_status_t ctls_build_ctls_record(ctls_context_t *context,
                                        const ctls_record_type_t type) {
    switch (type) {
        case CTLS_RECORD_TYPE_CLIENT_HELLO: return
                    ctls_build_ctls_record_client_hello(context);
        case CTLS_RECORD_TYPE_SERVER_HELLO: return
                    ctls_build_ctls_record_server_hello(context);
        case CTLS_RECORD_TYPE_ENCRYPTED_EXTENSIONS: return
                    ctls_build_record_encrypted_extensions(context);
        case CTLS_RECORD_TYPE_CERTIFICATE: return ctls_build_record_certificate(
                context);
        case CTLS_RECORD_TYPE_CERTIFICATE_VERIFY: return
                    ctls_build_record_certificate_verify(context);
        case CTLS_RECORD_TYPE_FINISHED: return ctls_build_record_finished(
                context);
        default: return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
    }
}

ctls_op_status_t
ctls_build_ctls_record_client_hello(ctls_context_t *context) {
    CTLS_CHECK_NULL(context);
    ctls_clear_record_buffer(&context->record);

    context->record.type = CTLS_RECORD_TYPE_CLIENT_HELLO;
    uint8_t random[CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM];
    uint8_t key_share[CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE];

    ctls_op_status_t result = ctls_generate_random(random);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;


    result = ctls_generate_ephemeral_public_key(
        key_share, CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    context->record.header.content_type = CTLS_CONTENT_TYPE_HANDSHAKE;
    context->record.header.sequence_number = context->sequence_number;

    context->record.body.client_hello.profile_id = context->profile.
            profile_id;
    memcpy(context->record.body.client_hello.random, random,
           CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_RANDOM);
    memcpy(context->record.body.client_hello.key_share, key_share,
           CTLS_WIRE_SIZE_RECORD_BODY_PARAMETER_KEY_SHARE);

    context->sequence_number++;
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t
ctls_build_ctls_record_server_hello(ctls_context_t *context) {
    // TODO0
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_build_record_encrypted_extensions(
    ctls_context_t *context) {
    // TODO
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t ctls_build_record_certificate(
    ctls_context_t *context) {
    // TODO
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t ctls_build_record_certificate_verify(
    ctls_context_t *context) {
    // TODO
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t
ctls_build_record_finished(ctls_context_t *context) {
    // TODO
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_handshake(ctls_context_t *context) {
    uint8_t buffer[256];
    size_t buffer_length = 0;

    // 1. build ClientHello into context->record
    ctls_op_status_t result = ctls_build_ctls_record(
        context, CTLS_RECORD_TYPE_CLIENT_HELLO);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_STATE_ERROR;
        return result;
    }

    // 2. serialize record to wire bytes
    result = ctls_record_serialize(&context->record, buffer, sizeof(buffer),
                                   &buffer_length);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_STATE_ERROR;
        return result;
    }

    // 3. send
    result = context->transport.fn_send(buffer, buffer_length);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_STATE_ERROR;
        return result;
    }

    ctls_update_transcript_hash(&context->record, &context->profile,
                                &context->transcript_hash.hash_operator);

    context->state = CTLS_STATE_WAIT_SERVER_HELLO;
    // 4. recv — blocks until server responds
    size_t recv_len = 0;
    result = context->transport.recd_receive(buffer, &recv_len, sizeof(buffer));
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_STATE_ERROR;
        return result;
    }

    // 5. deserialize into record
    ctls_clear_record_buffer(&context->record);
    result = ctls_record_deserialize(&context->record, buffer, recv_len);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_STATE_ERROR;
        return result;
    }

    // 6. parse ServerHello — next step
    context->state = CTLS_STATE_WAIT_ENCRYPTED_EXTENSIONS;


    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}
