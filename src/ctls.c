#include "ctls/ctls.h"

#include <stdbool.h>
#include "ctls/internal.h"
#include "crypto.c"
#include "ctls/bytes.h"


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

ctls_op_status_t ctls_write_body_length(uint8_t *buffer, size_t *offset,
                                        size_t const body_length) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);

    ctls_write_u16(buffer, offset, body_length);
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_record_serialize(ctls_record_t const *record,
                                       uint8_t *buffer,
                                       size_t const buffer_size,
                                       size_t *buffer_length) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);

    size_t offset = 0;
    size_t body_start = offset;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        // header: content_type (1 byte)
        if (offset + CTLS_WIRE_CONTENT_TYPE > buffer_size)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_OVERFLOW,
                .external_code = CTLS_OP_STATUS_OVERFLOW,
            };

        buffer[offset++] = record->content_type;

        if (offset + CTLS_WIRE_PROFILE_ID > buffer_size)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_OVERFLOW,
                .external_code = CTLS_OP_STATUS_OVERFLOW
            };

        // opaque profile_id<0..2^8-1>;
        buffer[offset++] = 0x01;
        buffer[offset++] = record->profile_id;

        // record body — depends on record type
        body_start = offset;
        offset += 2;

        switch (record->record_body.message_type) {
            case CTLS_HSMG_TYPE_CLIENT_HELLO: {
                // opaque Random[32];
                ctls_write_bytes(buffer, &offset, CTLS_WIRE_RANDOM,
                                 record->record_body.handshake_message_body.
                                 client_hello.random);

                // CipherSuite cipher_suites<2..2^16-2>;
                ctls_write_u16(buffer, &offset, 0x02);
                ctls_write_u16(buffer, &offset,
                               (uint16_t) record->record_body.
                               handshake_message_body.client_hello.
                               cipher_suite);

                // Extension extensions<1..2^16-1>;
                ctls_write_bytes(buffer, &offset, CTLS_WIRE_KEY_SHARE,
                                 record->record_body.handshake_message_body.
                                 client_hello.extensions.key_share_entity.
                                 key_share);
            }
            case CTLS_HSMG_TYPE_SERVER_HELLO: {
                // TODO
                break;
            }
            default:
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_INVALID,
                    .external_code = CTLS_OP_STATUS_INVALID,
                };
        }
    }
    if (record->type == CTLS_RECORD_TYPE_ENCRYPTED) {
    }


    // fill in body length
    ctls_write_body_length(buffer, &body_start,
                           (uint16_t) (offset - body_start));
    *buffer_length = offset;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_record_deserialize(ctls_record_t const *record,
                                         uint8_t *buffer,
                                         size_t buffer_length) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(record);

    size_t offset = 0;

    // TODO

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
