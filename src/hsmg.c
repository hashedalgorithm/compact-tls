//
// Created by SanjayKumar Kumaravelan on 16/04/26.
//

#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/hsmg.h"
#include "ctls/templates.h"


ctls_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg) {
    ctls_template_t const *template = ctls_template_get();
    ctls_crypto_t const *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t const result = ctls_random_generate(
            hshk_data->client_random,
            &hsmg->handshake_message_body.client_hello.random.buffer_length,
            template->random);
    hsmg->handshake_message_body.client_hello.random.buffer = hshk_data->client_random;

    if (result != CTLS_STATUS_SUCCESS) return result;

    hsmg->handshake_message_body.client_hello.cipher_suite = template->cipher_suite;
    hsmg->handshake_message_body.client_hello.protocol_version = template->protocol_version;
    hsmg->handshake_message_body.client_hello.legacy_session_id = 0x00;
    hsmg->handshake_message_body.client_hello.legacy_compression_methods = 0x00;

    return ctls_extn_client_hello_create(
            &hsmg->handshake_message_body.client_hello.extensions);
}


ctls_status_t ctls_hsmg_client_hello_to_struct(ctls_handshake_message_t *hsmg,
                                               uint8_t *buffer,
                                               ctls_size_t *offset,
                                               ctls_size_t buffer_size) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_hsmg_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_size_t const *buffer_size,
                                             ctls_handshake_message_t const *hsmg,
                                             ctls_wire_format_t const wire_format) {
    ctls_template_t const *template = ctls_template_get();
    CTLS_CHECK_NULL(template);

    ctls_size_t body_start = *offset;
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        offset += 2;

        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u16(buffer, offset, hsmg->sequence_number);

        ctls_write_bytes(buffer, offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer);

        if (template->cipher_suite == 0) {
            ctls_write_u16(buffer, offset,
                           sizeof(hsmg->handshake_message_body.client_hello.cipher_suite));
            ctls_write_u16(buffer, offset, CTLS_DEFAULT_SENTINEL);
        }

        ctls_status_t const result = ctls_extn_client_hello_to_wire(buffer, offset,
                &hsmg->handshake_message_body.client_hello.extensions,
                CTLS_WIRE_FORMAT_DEFAULT);

        ctls_write_u16(buffer, &body_start, *offset - body_start);

        return result;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_size_t hsmg_body_length_offset = *offset;
        *offset += 3;

        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2);
        ctls_write_bytes(buffer, offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer);
        ctls_write_u8(buffer, offset,
                      sizeof(hsmg->handshake_message_body.client_hello.legacy_session_id));
        ctls_write_u8(buffer, offset,
                      hsmg->handshake_message_body.client_hello.legacy_session_id);
        ctls_write_u16(buffer, offset,
                       sizeof(hsmg->handshake_message_body.client_hello.cipher_suite));
        ctls_write_u16(buffer, offset,
                       hsmg->handshake_message_body.client_hello.cipher_suite);
        ctls_write_u8(buffer, offset,
                      sizeof(hsmg->handshake_message_body.client_hello.legacy_compression_methods));
        ctls_write_u8(buffer, offset,
                      hsmg->handshake_message_body.client_hello.legacy_compression_methods);

        ctls_status_t const result = ctls_extn_client_hello_to_wire(buffer, offset,
                &hsmg->handshake_message_body.client_hello.extensions,
                CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u24(buffer, &hsmg_body_length_offset, *offset - hsmg_body_length_offset);

        return CTLS_STATUS_SUCCESS;
    }
    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_server_hello_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_hsmg_server_hello_to_struct(ctls_handshake_message_t *hsmg,
                                               uint8_t *buffer,
                                               ctls_size_t *offset,
                                               ctls_size_t buffer_size) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL_OFFSET(offset);

    hsmg->message_type = ctls_read_u8(buffer, offset);

    ctls_read_bytes(hshk_data->server_random, template->random, buffer, offset);
    hsmg->handshake_message_body.server_hello.random.buffer = hshk_data->server_random;
    hsmg->handshake_message_body.server_hello.random.buffer_length = template->random;

    hsmg->handshake_message_body.server_hello.cipher_suite = ctls_read_u16(buffer, offset);

    hsmg->handshake_message_body.server_hello.protocol_version = template->protocol_version;
    hsmg->handshake_message_body.server_hello.legacy_compression_method = 0;
    hsmg->handshake_message_body.server_hello.legacy_session_id_echo = 0;

    offset += 2;
    return ctls_extn_server_hello_to_struct(
            &hsmg->handshake_message_body.server_hello.extensions,
            buffer, offset);
}

ctls_status_t ctls_hsmg_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_size_t const *buffer_size,
                                             ctls_handshake_message_t const *hsmg,
                                             ctls_wire_format_t wire_format) {
    ctls_template_t const *template = ctls_template_get();
    CTLS_CHECK_NULL(template);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_size_t hsmg_body_length_offset = *offset;
        *offset += 3;

        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2);
        ctls_write_bytes(buffer, offset,
                         hsmg->handshake_message_body.server_hello.random.buffer_length,
                         hsmg->handshake_message_body.server_hello.random.buffer);
        ctls_write_u8(buffer, offset,
                      sizeof(hsmg->handshake_message_body.server_hello.legacy_session_id_echo));
        ctls_write_u8(buffer, offset,
                      hsmg->handshake_message_body.server_hello.legacy_session_id_echo);
        ctls_write_u16(buffer, offset,
                       hsmg->handshake_message_body.server_hello.cipher_suite);
        ctls_write_u8(buffer, offset,
                      sizeof(hsmg->handshake_message_body.server_hello.legacy_compression_method));
        ctls_write_u8(buffer, offset,
                      hsmg->handshake_message_body.server_hello.legacy_compression_method);

        ctls_status_t const result = ctls_extn_server_hello_to_wire(buffer, offset,
                &hsmg->handshake_message_body.server_hello.extensions,
                CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u24(buffer, &hsmg_body_length_offset, *offset - hsmg_body_length_offset);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_encrypted_extensions_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_hsmg_encrypted_extensions_to_struct(ctls_handshake_message_t *hsmg,
                                                       uint8_t *buffer) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);

    return ctls_extn_encrypted_extensions_to_struct(
            &hsmg->handshake_message_body.encrypted_extensions.extensions);
}

ctls_status_t ctls_hsmg_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_handshake_message_t const *hsmg,
                                                     ctls_wire_format_t wire_format) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(template);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_size_t extensions_length_offset = *offset;

        ctls_status_t const result = ctls_extn_encrypted_extensions_to_wire(buffer, offset,
                &hsmg->handshake_message_body.encrypted_extensions.extensions,
                CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &extensions_length_offset,
                       *offset - extensions_length_offset);
        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_certificate_request_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_hsmg_certificate_request_to_struct(ctls_handshake_message_t *hsmg,
                                                      uint8_t *buffer) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(hshk_data);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);

    ctls_size_t const certificate_request_context_length = ctls_read_u8(buffer, &offset);
    if (certificate_request_context_length > 0) {
        ctls_read_bytes(hshk_data->certificate_request_context,
                        certificate_request_context_length, buffer, &offset);
    }

    return ctls_extn_certificate_request_to_struct(
            &hsmg->handshake_message_body.certificate_request.extensions);
}

ctls_status_t ctls_hsmg_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_handshake_message_t const *hsmg,
                                                    ctls_wire_format_t wire_format) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(template);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u8(buffer, offset,
                      hsmg->handshake_message_body.certificate_request.
                      certificate_request_context.buffer_length);

        if (hsmg->handshake_message_body.certificate_request.certificate_request_context.
            buffer_length > 0) {
            ctls_write_bytes(buffer, offset,
                             hsmg->handshake_message_body.certificate_request.
                             certificate_request_context.buffer_length,
                             hsmg->handshake_message_body.certificate_request.
                             certificate_request_context.buffer);
        }

        ctls_size_t extensions_length_offset = *offset;
        ctls_status_t const result = ctls_extn_certificate_request_to_wire(buffer, offset,
                &hsmg->handshake_message_body.certificate_request.extensions,
                CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer, &extensions_length_offset, *offset - extensions_length_offset);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

    }


    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_hsmg_certificate_verify_create() {
}

ctls_op_status_t ctls_hsmg_certificate_verify_to_struct() {
}

ctls_op_status_t ctls_hsmg_certificate_verify_to_wire() {
}

ctls_op_status_t ctls_hsmg_finished_create() {
}

ctls_op_status_t ctls_hsmg_finished_to_struct() {
}

ctls_op_status_t ctls_hsmg_finished_to_wire() {
}

