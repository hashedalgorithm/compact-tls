//
// Created by SanjayKumar Kumaravelan on 16/04/26.
//

#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/hsmg.h"
#include "ctls/templates.h"


ctls_op_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg,
                                               ctls_hshk_buffer_t *hshk_buffer,
                                               ctls_template_t const *template) {
    ctls_op_status_t const result = ctls_random_generate(hshk_buffer->buffer,
                                                         &hshk_buffer->buffer_length,
                                                         &hsmg->handshake_message_body.
                                                         client_hello.random.
                                                         buffer_length,
                                                         template->random);
    hsmg->handshake_message_body.client_hello.random.buffer = &hshk_buffer->buffer[
        hshk_buffer->buffer_length - 1];

    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    hsmg->handshake_message_body.client_hello.cipher_suite = template->cipher_suite;
    hsmg->handshake_message_body.client_hello.protocol_version = template->
            protocol_version;
    hsmg->handshake_message_body.client_hello.legacy_session_id = 0x00;
    hsmg->handshake_message_body.client_hello.legacy_compression_methods = 0x00;

    return ctls_extn_client_hello_create(&hsmg->handshake_message_body.client_hello.
                                         extensions,
                                         hshk_buffer,
                                         template);
}


ctls_op_status_t ctls_hsmg_client_hello_to_struct() {
}

ctls_op_status_t ctls_hsmg_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_size_t const *buffer_size,
                                                ctls_handshake_message_t const *hsmg,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t const wire_format) {
    ctls_size_t body_start = *offset;
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        offset += 2;

        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u16(buffer, offset, hsmg->sequence_number);

        // opaque Random[32];
        ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer);

        if (template->cipher_suite == 0) {
            // CipherSuite cipher_suites<2..2^16-2>;
            ctls_write_u16(buffer, offset, 0x02);
            ctls_write_u16(buffer, offset, CTLS_DEFAULT_CIPHER_SUITE);
        }

        // Extension extensions<1..2^16-1>;
        ctls_op_status_t const result = ctls_extn_client_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.client_hello.extensions,
            template,
            CTLS_WIRE_FORMAT_DEFAULT);

        ctls_size_t const body_length = *offset - body_start;
        ctls_write_u16(buffer, &body_start, body_length);

        return result;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_hsmg_server_hello_create() {
}

ctls_op_status_t ctls_hsmg_server_hello_to_struct() {
}

ctls_op_status_t ctls_hsmg_server_hello_to_wire() {
}

ctls_op_status_t ctls_hsmg_encrypted_extensions_create() {
}

ctls_op_status_t ctls_hsmg_encrypted_extensions_to_struct() {
}

ctls_op_status_t ctls_hsmg_encrypted_extensions_to_wire() {
}

ctls_op_status_t ctls_hsmg_certificate_create() {
}

ctls_op_status_t ctls_hsmg_certificate_to_struct() {
}

ctls_op_status_t ctls_hsmg_certificate_to_wire() {
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

