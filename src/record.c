//
// Created by Sanjay Kumar Kumaravelan on 15/04/26.
//

#include <string.h>
#include "ctls/ctls.h"
#include "ctls/bytes.h"
#include "ctls/hsmg.h"
#include "ctls/record.h"
#include "ctls/templates.h"

ctls_op_status_t ctls_build_unified_header(const ctls_recd_config_octet_t *config,
                                           uint16_t sequence_number,
                                           uint16_t length,
                                           uint8_t *buffer,
                                           ctls_size_t *buffer_length) {
    CTLS_CHECK_NULL(config);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);

    ctls_size_t offset = 0;

    /* ---- config octet ---- */
    /* fixed bits 7-5 = 0b001, per RFC 9147 §4 */
    uint8_t octet = CTLS_RECD_CONFIG_OCTET_FIXED_VALUE;

    /* C bit (4): CID present */
    if (config->c_bit) octet |= CTLS_RECD_CONFIG_OCTET_C_MASK;

    /* S bit (3): sequence number length — 0=8bit, 1=16bit */
    if (config->s_bit) octet |= CTLS_RECD_CONFIG_OCTET_S_MASK;

    /* L bit (2): length field present */
    if (config->l_bit) octet |= CTLS_RECD_CONFIG_OCTET_L_MASK;

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

ctls_op_status_t ctls_write_body_length(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        ctls_size_t const body_length) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);

    ctls_write_u16(buffer, offset, body_length);
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_size_t buffer_size,
                                                ctls_record_t const *record,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(record);


    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        // § ctls draft 10: 2.2 - ContentType content_type = ctls_handshake;
        if (sizeof(record->content_type) + *offset > buffer_size)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_OVERFLOW,
                .external_code = CTLS_OP_STATUS_OVERFLOW,
            };

        ctls_write_u8(buffer, offset, record->content_type);

        if ((sizeof(record->profile_id) + sizeof(uint8_t)) + *offset > buffer_size)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_OVERFLOW,
                .external_code = CTLS_OP_STATUS_OVERFLOW
            };

        // opaque profile_id<0..2^8-1>;
        ctls_write_u8(buffer, offset, sizeof(record->profile_id));
        ctls_write_u8(buffer, offset, record->profile_id);

        return ctls_hsmg_client_hello_to_wire(buffer,
                                              offset,
                                              &buffer_size,
                                              &record->record_body,
                                              template,
                                              CTLS_WIRE_FORMAT_DEFAULT);
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, record->content_type);
        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2);

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        ctls_op_status_t const result = ctls_hsmg_client_hello_to_wire(buffer,
            offset,
            &buffer_size,
            &record->record_body,
            template,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);

        if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &record_body_length, *offset - record_body_length);
    }
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_record_serialize(ctls_template_t const *template,
                                       ctls_record_t const *record,
                                       uint8_t *buffer,
                                       ctls_size_t const buffer_size,
                                       ctls_size_t *buffer_length) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);

    ctls_size_t offset = 0;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        switch (record->record_body.message_type) {
            case CTLS_HSMG_TYPE_CLIENT_HELLO: {
                ctls_recd_client_hello_to_wire(buffer,
                                               &offset,
                                               buffer_size,
                                               record,
                                               template,
                                               CTLS_WIRE_FORMAT_DEFAULT);
            }
            case CTLS_HSMG_TYPE_SERVER_HELLO: {
                // TODO
                // ctls_recd_server_hello_to_wire(buffer, &offset, &buffer_size,
                //                                record, template,
                //                                CTLS_WIRE_FORMAT_DEFAULT);
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


    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_record_deserialize(ctls_record_t *record,
                                         ctls_template_t const *template,
                                         ctls_hshk_buffer_t *hshk_buffer,
                                         ctls_hshk_data_t *hshk_data,
                                         uint8_t *buffer,
                                         ctls_size_t buffer_length) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);

    ctls_size_t offset = 0;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        switch (record->record_body.message_type) {
            case CTLS_HSMG_TYPE_CLIENT_HELLO: {
                // ctls_recd_client_hello_to_struct();
            }
            break;
            case CTLS_HSMG_TYPE_SERVER_HELLO: {
                ctls_recd_server_hello_to_struct(record,
                                                 template,
                                                 hshk_buffer,
                                                 hshk_data,
                                                 buffer,
                                                 &offset,
                                                 buffer_length);
            }
            break;
            default:
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_INVALID,
                    .external_code = CTLS_OP_STATUS_INVALID,
                };
        }
    }

    if (record->type == CTLS_RECORD_TYPE_ENCRYPTED) {
        switch (record->record_body.message_type) {
            case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS: {
            }
            break;
        }
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_recd_buffer_clear(ctls_record_t *record_buffer) {
    memset(record_buffer, 0, sizeof(ctls_record_t));

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t ctls_recd_client_hello_create(ctls_record_t *record,
                                               ctls_hshk_buffer_t *hshk_buffer,
                                               ctls_template_t const *template,
                                               ctls_hshk_data_t *hshk_data) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);

    ctls_op_status_t const result = ctls_recd_buffer_clear(record);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    record->profile_id = template->profile_id;
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->record_body.message_type = CTLS_HSMG_TYPE_CLIENT_HELLO;
    record->record_body.sequence_number = 0;

    return ctls_hsmg_client_hello_create(&record->record_body,
                                         hshk_buffer,
                                         template,
                                         hshk_data);
}

ctls_op_status_t ctls_recd_client_hello_to_struct() {
}


ctls_op_status_t ctls_recd_server_hello_create() {
}

ctls_op_status_t ctls_recd_server_hello_to_struct(ctls_record_t *record,
                                                  ctls_template_t const *template,
                                                  ctls_hshk_buffer_t *hshk_buffer,
                                                  ctls_hshk_data_t *hshk_data,
                                                  uint8_t *buffer,
                                                  ctls_size_t *offset,
                                                  ctls_size_t buffer_size) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(hshk_buffer);
    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL(offset);

    record->content_type = ctls_read_u8(buffer, offset);
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->sequence_number = 0;
    record->length = ctls_read_u16(buffer, offset);

    return ctls_hsmg_server_hello_to_struct(&record->record_body,
                                            template,
                                            hshk_buffer,
                                            hshk_data,
                                            buffer,
                                            offset,
                                            buffer_size);
}

ctls_op_status_t ctls_recd_server_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_size_t buffer_size,
                                                ctls_record_t const *record,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format) {
    CTLS_CHECK_NULL(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);
    ctls_size_t length = 0;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, record->content_type);
        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3);

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        ctls_op_status_t const result = ctls_hsmg_server_hello_to_wire(buffer,
            offset,
            &buffer_size,
            &record->record_body,
            template,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);

        if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &record_body_length, *offset - record_body_length);
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_recd_encrypted_extensions_create() {
}

ctls_op_status_t ctls_recd_encrypted_extensions_to_struct() {
}

ctls_op_status_t ctls_recd_encrypted_extensions_to_wire() {
}

ctls_op_status_t ctls_recd_certificate_create() {
}

ctls_op_status_t ctls_recd_certificate_to_struct() {
}

ctls_op_status_t ctls_recd_certificate_to_wire() {
}

ctls_op_status_t ctls_recd_certificate_verify_create() {
}

ctls_op_status_t ctls_recd_certificate_verify_to_struct() {
}

ctls_op_status_t ctls_recd_certificate_verify_to_wire() {
}

ctls_op_status_t ctls_recd_finished_create() {
}

ctls_op_status_t ctls_recd_finished_to_struct() {
}

ctls_op_status_t ctls_recd_finished_to_wire() {
}
