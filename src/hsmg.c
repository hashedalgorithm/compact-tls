//
// Created by SanjayKumar Kumaravelan on 16/04/26.
//

#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/hsmg.h"
#include "ctls/templates.h"


ctls_op_status_t ctls_hsmg_client_hello_to_struct() {
}

ctls_op_status_t ctls_hsmg_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_size_t const *buffer_size,
                                                ctls_handshake_message_t const *hsmg,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t const wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
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


ctls_op_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg,
                                               ctls_hshk_buffer_t *hshk_buffer,
                                               ctls_template_t const *template) {
    ctls_op_status_t const result =
            ctls_random_generate(&hshk_buffer->buffer[hshk_buffer->buffer_length]);
    ctls_hshk_buffer_offset_update(&hshk_buffer->buffer_length, template->random);

    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    hsmg->handshake_message_body.client_hello.cipher_suite = template->cipher_suite;
    hsmg->handshake_message_body.client_hello.protocol_version = template->
            protocol_version;
    hsmg->handshake_message_body.client_hello.legacy_session_id = 0x00;
    hsmg->handshake_message_body.client_hello.legacy_compression_methods = 0x00;

    return ctls_extn_client_hello_create(&hsmg->handshake_message_body.client_hello,
                                         hshk_buffer,
                                         template);
}

