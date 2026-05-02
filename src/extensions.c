//
// Created by Sanjay Kumar Kumaravelan on 18/04/26.
//

#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/templates.h"
#include "ctls/bytes.h"

uint8_t ctls_expected_extensions_size_get(
    ctls_tmpl_expected_extensions_t const *expected_extensions) {
    return sizeof(*expected_extensions) / sizeof((*expected_extensions)[0]);
}

ctls_op_status_t ctls_extn_client_hello_create(
    ctls_extn_client_hello_t *client_hello_extensions,
    ctls_hshk_buffer_t *hshk_buffer,
    ctls_template_t const *template) {
    uint8_t const size_of_expected_extensions =
            ctls_expected_extensions_size_get(&template->client_hello_extension.
                                              expected_extensions);

    // server_name
    if (template->client_hello_extension.predefined_extensions.server_name.data != NULL) {
        client_hello_extensions->server_name.form = CTLS_DATA_FORM_OPAQUE;
        client_hello_extensions->server_name.extension_type = CTLS_EXTN_TYPE_SERVER_NAME;
        client_hello_extensions->server_name.opaque.buffer_length = template->
                client_hello_extension.predefined_extensions.server_name.length;
        client_hello_extensions->server_name.opaque.buffer = template->
                client_hello_extension.predefined_extensions.server_name.data;
    }

    // max_fragment_length
    if (template->client_hello_extension.predefined_extensions.maximum_fragment_length ==
        0) {
        client_hello_extensions->maximum_fragment_length = template->
                client_hello_extension.predefined_extensions.maximum_fragment_length;
    }

    // certificate_status_request
    if (template->client_hello_extension.predefined_extensions.certificate_status_request.
        data != NULL) {
        client_hello_extensions->certificate_status_request.form = CTLS_DATA_FORM_OPAQUE;
        client_hello_extensions->certificate_status_request.extension_type =
                CTLS_EXTN_TYPE_STATUS_REQUEST;
        client_hello_extensions->certificate_status_request.opaque.buffer_length =
                template->client_hello_extension.predefined_extensions.
                certificate_status_request.length;
        client_hello_extensions->certificate_status_request.opaque.buffer = template->
                client_hello_extension.predefined_extensions.certificate_status_request.
                data;
    }

    // heartbeat
    if (template->client_hello_extension.predefined_extensions.heartbeat_mode != 0) {
        client_hello_extensions->heartbeat_mode = template->client_hello_extension.
                predefined_extensions.heartbeat_mode;
    }

    // alpn
    if (template->client_hello_extension.predefined_extensions.alpn.data != NULL) {
        client_hello_extensions->alpn.form = CTLS_DATA_FORM_OPAQUE;
        client_hello_extensions->alpn.extension_type =
                CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
        client_hello_extensions->alpn.opaque.buffer = template->client_hello_extension.
                predefined_extensions.alpn.data;
        client_hello_extensions->alpn.opaque.buffer_length = template->
                client_hello_extension.predefined_extensions.alpn.length;
    }

    // client_certificate_type
    if (template->client_hello_extension.predefined_extensions.client_certificate_type !=
        0) {
        client_hello_extensions->client_certificate_type = template->
                client_hello_extension.predefined_extensions.client_certificate_type;
    }

    // server_certificate_type
    if (template->client_hello_extension.predefined_extensions.server_certificate_type !=
        0) {
        client_hello_extensions->server_certificate_type = template->
                client_hello_extension.predefined_extensions.server_certificate_type;
    }

    // psk_key_exchange_modes
    if (template->client_hello_extension.predefined_extensions.psk_key_exchange_modes !=
        0) {
        client_hello_extensions->psk_key_exchange_modes = template->client_hello_extension
                .predefined_extensions.psk_key_exchange_modes;
    }

    // post_handshake_auth
    if (template->client_hello_extension.predefined_extensions.post_handshake_auth != 0) {
        client_hello_extensions->post_handshake_auth = template->client_hello_extension.
                predefined_extensions.post_handshake_auth;
    }


    // signature_algorithm_cert
    if (template->client_hello_extension.predefined_extensions.signature_algorithm_cert !=
        0) {
        client_hello_extensions->signature_algorithm_cert = template->
                client_hello_extension.predefined_extensions.signature_algorithm_cert;
    }

    for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
        if (template->client_hello_extension.expected_extensions[i] !=
            CTLS_EXTN_TYPE_KEY_SHARE) {
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
        }


        ctls_op_status_t const result =
                ctls_ephemeral_public_key_generate(hshk_buffer->buffer,
                                                   &hshk_buffer->buffer_length,
                                                   &client_hello_extensions->
                                                   key_share_entity.key_share.
                                                   buffer_length);

        if (result.code != CTLS_OP_STATUS_SUCCESS) return result;
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}


ctls_op_status_t ctls_extn_client_hello_to_struct(uint8_t *buffer,
                                                  ctls_size_t *offset,
                                                  ctls_hsmg_client_hello_t *client_hello,
                                                  ctls_template_t const *template) {
}

ctls_op_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_client_hello_t const *
                                                client_hello_extensions,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format) {
    uint8_t const size_of_expected_extensions =
            ctls_expected_extensions_size_get(&template->client_hello_extension.
                                              expected_extensions);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        // Extension extensions<1..2^16-1>;
        for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
            if (template->client_hello_extension.expected_extensions[i] !=
                CTLS_EXTN_TYPE_KEY_SHARE) {
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_INVALID,
                    .external_code = CTLS_OP_STATUS_INVALID,
                };
            }

            ctls_size_t key_share_start = *offset;
            if (template->dhe_group.key_share_length == 0) {
                ctls_write_u16(buffer,
                               &key_share_start,
                               client_hello_extensions->key_share_entity.key_share.
                               buffer_length);
            }

            ctls_write_bytes(buffer,
                             offset,
                             client_hello_extensions->key_share_entity.key_share.
                             buffer_length,
                             client_hello_extensions->key_share_entity.key_share.buffer);
        }

        return (ctls_op_status_t){
            . source = CTLS_ERROR_SOURCE_INTERNAL,
            . code = CTLS_OP_STATUS_SUCCESS,
            . external_code = CTLS_OP_STATUS_SUCCESS,
        };
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }
    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_INVALID,
        . external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_hsmg_server_hello_t *server_hello,
                                                ctls_wire_format_t const wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }

    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_INVALID,
        . external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_server_hello_to_struct() {
}

ctls_op_status_t ctls_extn_server_hello_create(ctls_hsmg_server_hello_t *server_hello,
                                               ctls_template_t const *template) {
}

ctls_op_status_t ctls_extn_encrypted_extensions_to_wire(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_wire_format_t const wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }

    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_INVALID,
        . external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_encrypted_extensions_to_struct() {
}

ctls_op_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_template_t const *template) {
}



