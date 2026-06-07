// Created by Sanjay Kumar Kumaravelan on 15/04/26.
//

#include <string.h>
#include "ctls/ctls.h"
#include "ctls/bytes.h"
#include "ctls/hsmg.h"
#include "ctls/record.h"
#include "ctls/templates.h"


ctls_status_t ctls_unified_header_build(ctls_unified_header_t *unified_header,
                                        uint16_t const sequence_number,
                                        uint16_t const length,
                                        uint64_t const *epoch) {
    CTLS_CHECK_NULL_STRUCT(unified_header);
    CTLS_CHECK_NULL_BUFFER(epoch);

    unified_header->config_octet.c_bit = 0;
    unified_header->config_octet.s_bit = (sequence_number > 0xFFu) ? 1u : 0u;
    unified_header->config_octet.l_bit = (length > 0u) ? 1u : 0u;
    unified_header->config_octet.epoch = ctls_epoch_compress(epoch);

    unified_header->sequence_number = sequence_number;
    unified_header->length = length;
    unified_header->epoch = *epoch;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_unified_header_serialize(ctls_unified_header_t const *unified_header,
                                            uint8_t *buffer,
                                            ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(unified_header);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (unified_header->config_octet.c_bit != 0) return CTLS_STATUS_RECD_UNSUPPORTED_CID;

    if (unified_header->config_octet.s_bit != 0 && unified_header->config_octet.s_bit !=
        1) return CTLS_STATUS_RECD_INVALID_SEQ_LEN;

    uint8_t octet = CTLS_RECD_CONFIG_OCTET_FIXED_VALUE;
    if (unified_header->config_octet.c_bit) octet |= CTLS_RECD_CONFIG_OCTET_C_MASK;
    if (unified_header->config_octet.s_bit) octet |= CTLS_RECD_CONFIG_OCTET_S_MASK;
    if (unified_header->config_octet.l_bit) octet |= CTLS_RECD_CONFIG_OCTET_L_MASK;
    octet |= ctls_epoch_compress(&unified_header->epoch) &
            CTLS_RECD_CONFIG_OCTET_EPOCH_MASK;

    buffer[(*offset)++] = octet;

    if (unified_header->config_octet.s_bit == 0) {
        ctls_write_u8(buffer, offset, (uint8_t) unified_header->sequence_number);
    } else {
        ctls_write_u16(buffer, offset, unified_header->sequence_number);
    }

    if (unified_header->config_octet.l_bit == 1) {
        ctls_write_u16(buffer, offset, unified_header->length);
    }

    return CTLS_STATUS_SUCCESS;
}


ctls_status_t ctls_unified_header_deserialize(ctls_unified_header_t *unified_header,
                                              uint8_t const *buffer,
                                              ctls_size_t *offset) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(unified_header);
    CTLS_CHECK_BOUNDS(*offset, 2, CTLS_SIZE_WIRE_BUFFER);

    uint8_t const first_part = buffer[(*offset)++];
    uint8_t const second_part = buffer[(*offset)++];

    unified_header->config_octet.c_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_C_MASK) != 0;
    unified_header->config_octet.s_bit = second_part;
    unified_header->config_octet.l_bit =
            (first_part & CTLS_RECD_CONFIG_OCTET_L_MASK) != 0;
    unified_header->config_octet.epoch = first_part & CTLS_RECD_CONFIG_OCTET_EPOCH_MASK;

    if (unified_header->config_octet.c_bit == 1) return CTLS_STATUS_RECD_UNSUPPORTED_CID;

    if (unified_header->config_octet.s_bit > 1 || unified_header->config_octet.s_bit < 0)
        return CTLS_STATUS_RECD_INVALID_SEQ_LEN;

    if (unified_header->config_octet.s_bit == 0) {
        unified_header->sequence_number = ctls_read_u8(buffer, offset);
    } else {
        unified_header->sequence_number = ctls_read_u16(buffer, offset);
    }
    if (unified_header->config_octet.l_bit == 1) {
        unified_header->length = ctls_read_u16(buffer, offset);
    }

    ctls_epoch_expand(unified_header->config_octet.epoch, &unified_header->epoch);

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(record);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        if (sizeof(record->content_type) + *offset > CTLS_SIZE_WIRE_BUFFER) return
                CTLS_STATUS_BUFFER_OVERFLOW;

        ctls_write_u8(buffer, offset, record->content_type);

        if ((sizeof(record->profile_id) + sizeof(uint8_t)) + *offset >
            CTLS_SIZE_WIRE_BUFFER) return CTLS_STATUS_BUFFER_OVERFLOW;

        ctls_write_u8(buffer, offset, sizeof(record->profile_id));
        ctls_write_u8(buffer, offset, record->profile_id);

        return ctls_hsmg_client_hello_to_wire(buffer,
                                              offset,
                                              &record->record_body,
                                              CTLS_WIRE_FORMAT_DEFAULT);
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, record->content_type);
        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3);

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        ctls_status_t const result = ctls_hsmg_client_hello_to_wire(buffer,
            offset,
            &record->record_body,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &record_body_length, *offset - record_body_length);

        return CTLS_STATUS_SUCCESS;
    }
    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_record_serialize(ctls_record_t const *record,
                                    uint8_t *buffer,
                                    ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = ctls_wire_buffer_clear(buffer, offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (record->type == CTLS_RECORD_TYPE_PLAINTEXT) {
        switch (record->record_body.message_type) {
            case CTLS_HSMG_TYPE_CLIENT_HELLO:
                result = ctls_recd_client_hello_to_wire(buffer,
                                                        offset,
                                                        record,
                                                        CTLS_WIRE_FORMAT_DEFAULT);
                break;
            case CTLS_HSMG_TYPE_SERVER_HELLO:
                /* TODO */
                break;
            default:
                return CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE;
        }
    }
    if (record->type == CTLS_RECORD_TYPE_ENCRYPTED) {
    }

    return result;
}

ctls_status_t ctls_record_deserialize(ctls_record_t *record,
                                      ctls_hsmg_type_t const hsmg_type,
                                      uint8_t const *buffer,
                                      ctls_entity_t const entity) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    ctls_size_t offset = 0;

    result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    switch (hsmg_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO:
            /* todo — server-side logic */
            break;
        case CTLS_HSMG_TYPE_SERVER_HELLO:
            result = ctls_recd_server_hello_to_struct(record, buffer, &offset);
            break;
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            result = ctls_recd_encrypted_extensions_to_struct(record, buffer);
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            result = ctls_recd_certificate_request_to_struct(record, buffer);
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE:
            result = ctls_recd_certificate_to_struct(record, buffer);
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE_VERIFY:
            result = ctls_recd_certificate_verify_to_struct(record, buffer, entity);
            break;
        default:
            result = CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE;
    }

    return result;
}

ctls_status_t ctls_recd_buffer_clear(ctls_record_t *record_buffer) {
    CTLS_CHECK_NULL_STRUCT(record_buffer);

    memset(record_buffer, 0, sizeof(ctls_record_t));

    return CTLS_STATUS_SUCCESS;
}


ctls_status_t ctls_recd_client_hello_create(ctls_record_t *record) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->profile_id = template->profile_id;
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->record_body.message_type = CTLS_HSMG_TYPE_CLIENT_HELLO;
    record->record_body.sequence_number = 0;

    return ctls_hsmg_client_hello_create(&record->record_body);
}

ctls_status_t ctls_recd_client_hello_to_struct() {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}


ctls_status_t ctls_recd_server_hello_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_recd_server_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    record->content_type = ctls_read_u8(buffer, offset);
    record->type = CTLS_RECORD_TYPE_PLAINTEXT;
    record->unified_header.sequence_number = 0;
    record->unified_header.length = ctls_read_u16(buffer, offset);

    return ctls_hsmg_server_hello_to_struct(&record->record_body, buffer, offset);
}

ctls_status_t ctls_recd_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, record->content_type);
        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_3);

        ctls_size_t record_body_length = *offset;
        *offset += 2;
        ctls_status_t const result = ctls_hsmg_server_hello_to_wire(buffer,
            offset,
            &record->record_body,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &record_body_length, *offset - record_body_length);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_encrypted_extensions_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_recd_encrypted_extensions_to_struct(ctls_record_t *record,
                                                       uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    size_t plaintext_offset = 0;
    ctls_size_t offset = 0;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    ctls_status_t result = ctls_unified_header_deserialize(&record->unified_header,
                                                           buffer,
                                                           &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_decrypt(&record->unified_header.sequence_number,
                          buffer,
                          offset,
                          plaintext,
                          plaintext_offset,
                          plaintext,
                          &plaintext_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_encrypted_extensions_to_struct(&record->record_body, plaintext);
}

ctls_status_t ctls_recd_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_record_t const *record,
                                                     ctls_wire_format_t const
                                                     wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_encrypted_extensions_to_wire(buffer,
            offset,
            &record->record_body,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_certificate_request_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_recd_certificate_request_to_struct(ctls_record_t *record,
                                                      uint8_t const *buffer) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);

    if (template->mutual_auth == 0) return CTLS_STATUS_RECD_NO_MUTUAL_AUTH;

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    size_t plaintext_offset = 0;
    ctls_size_t offset = 0;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    ctls_status_t result = ctls_unified_header_deserialize(&record->unified_header,
                                                           buffer,
                                                           &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_decrypt(&record->unified_header.sequence_number,
                          buffer,
                          offset,
                          plaintext,
                          plaintext_offset,
                          plaintext,
                          &plaintext_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_certificate_request_to_struct(&record->record_body, plaintext);
}

ctls_status_t ctls_recd_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_record_t const *record,
                                                    ctls_wire_format_t const
                                                    wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_certificate_request_to_wire(buffer,
            offset,
            &record->record_body,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_certificate_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_recd_certificate_to_struct(ctls_record_t *record,
                                              uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    size_t plaintext_offset = 0;
    ctls_size_t offset = 0;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    ctls_status_t result = ctls_unified_header_deserialize(&record->unified_header,
                                                           buffer,
                                                           &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_decrypt(&record->unified_header.sequence_number,
                          buffer,
                          offset,
                          plaintext,
                          plaintext_offset,
                          plaintext,
                          &plaintext_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_certificate_to_struct(&record->record_body, plaintext);
}

ctls_status_t ctls_recd_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_record_t const *record,
                                            ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_certificate_to_wire(buffer,
            offset,
            &record->record_body,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_recd_certificate_verify_create(ctls_record_t *record) {
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t const result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    record->record_body.message_type = CTLS_HSMG_TYPE_CERTIFICATE_VERIFY;
    record->record_body.sequence_number = 0;

    return ctls_hsmg_certificate_verify_create();
}

ctls_status_t ctls_recd_certificate_verify_to_struct(ctls_record_t *record,
                                                     uint8_t const *buffer,
                                                     ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
    size_t plaintext_offset = 0;
    ctls_size_t offset = 0;

    record->type = CTLS_RECORD_TYPE_ENCRYPTED;
    ctls_status_t result = ctls_unified_header_deserialize(&record->unified_header,
                                                           buffer,
                                                           &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_decrypt(&record->unified_header.sequence_number,
                          buffer,
                          offset,
                          plaintext,
                          plaintext_offset,
                          plaintext,
                          &plaintext_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_certificate_verify_to_struct(&record->record_body,
                                                  plaintext,
                                                  entity);
}

ctls_status_t ctls_recd_certificate_verify_to_wire(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_record_t const *record,
                                                   ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_STRUCT(record);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    };
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_unified_header_serialize(&record->unified_header, buffer, offset);

        ctls_status_t const result = ctls_hsmg_certificate_verify_to_wire(buffer,
            offset,
            &record->record_body,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_RECD_INVALID_WIRE_FORMAT;
}

}

ctls_op_status_t ctls_recd_finished_to_struct() {
}

ctls_op_status_t ctls_recd_finished_to_wire() {
}
