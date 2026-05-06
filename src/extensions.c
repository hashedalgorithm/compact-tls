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
    ctls_template_t const *template,
    ctls_hshk_data_t *hshk_data) {
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

    // supported_groups
    if (template->dhe_group.dhe_group != CTLS_EXTN_DHE_GROUP_SENTINEL) {
        client_hello_extensions->supported_groups.form = CTLS_DATA_FORM_PARSED;
        client_hello_extensions->supported_groups.extension_type =
                CTLS_EXTN_TYPE_SUPPORTED_GROUPS;
        client_hello_extensions->supported_groups.supported_group = template->dhe_group.
                dhe_group;
    }

    // signature_algorithms
    if (template->signature_algorithm.signature_algorithm_type !=
        CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL) {
        client_hello_extensions->signature_algorithm.form = CTLS_DATA_FORM_PARSED;
        client_hello_extensions->signature_algorithm.extension_type =
                CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS;
        client_hello_extensions->signature_algorithm.signature_algorithm = template->
                signature_algorithm.signature_algorithm_type;
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

    // supported_versions
    client_hello_extensions->supported_versions.extension_type =
            CTLS_EXTN_TYPE_SUPPORTED_VERSIONS;
    client_hello_extensions->supported_versions.form = CTLS_DATA_FORM_PARSED;
    client_hello_extensions->supported_versions.version =
            (template->protocol_version != CTLS_HSMG_PROTOCOL_VERSION_SENTINEL)
                ? template->protocol_version
                : CTLS_HSMG_PROTOCOL_VERSION_1_3;

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


        client_hello_extensions->key_share_entity.extension_type =
                CTLS_EXTN_TYPE_KEY_SHARE;
        client_hello_extensions->key_share_entity.form = CTLS_DATA_FORM_PARSED;
        client_hello_extensions->key_share_entity.key_share.buffer = &hshk_buffer->buffer[
            hshk_buffer->buffer_length];

        ctls_op_status_t const result =
                ctls_ephemeral_public_key_generate(hshk_buffer->buffer,
                                                   &hshk_buffer->buffer_length,
                                                   &client_hello_extensions->
                                                   key_share_entity.key_share.
                                                   buffer_length);

        hshk_data->client_key_share.buffer = client_hello_extensions->key_share_entity.
                key_share.buffer;
        hshk_data->client_key_share.buffer_length = client_hello_extensions->
                key_share_entity.key_share.buffer_length;

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
        ctls_size_t extensions_length_offset = *offset;

        // server_name
        if (client_hello_extensions->server_name.form != CTLS_DATA_FORM_SENTINEL) {
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->server_name.extension_type);

            if (client_hello_extensions->server_name.form == CTLS_DATA_FORM_OPAQUE) {
                ctls_write_u16(buffer,
                               offset,
                               client_hello_extensions->server_name.opaque.buffer_length);
                ctls_write_bytes(buffer,
                                 offset,
                                 client_hello_extensions->server_name.opaque.
                                 buffer_length,
                                 client_hello_extensions->server_name.opaque.buffer);
            } else {
                extensions_length_offset = *offset;
                offset += 2;


                ctls_size_t const server_name_list_count =
                        sizeof(client_hello_extensions->server_name.parsed_list) / sizeof(
                            client_hello_extensions->server_name.parsed_list[0]);

                for (ctls_size_t i = 0; i < server_name_list_count; i++) {
                    ctls_write_u8(buffer,
                                  offset,
                                  client_hello_extensions->server_name.parsed_list[i].
                                  name_type);
                    ctls_write_u16(buffer,
                                   offset,
                                   client_hello_extensions->server_name.parsed_list[i].
                                   server_name.buffer_length);
                    ctls_write_bytes(buffer,
                                     offset,
                                     client_hello_extensions->server_name.parsed_list[i].
                                     server_name.buffer_length,
                                     client_hello_extensions->server_name.parsed_list[i].
                                     server_name.buffer);
                }

                ctls_write_u16(buffer,
                               &extensions_length_offset,
                               *offset - extensions_length_offset);
            }
        }

        // max fragment length
        if (client_hello_extensions->maximum_fragment_length != 0) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(client_hello_extensions->maximum_fragment_length));
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->maximum_fragment_length);
        }

        // certificate status request
        if (client_hello_extensions->certificate_status_request.form !=
            CTLS_DATA_FORM_SENTINEL) {
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->certificate_status_request.
                           extension_type);

            if (client_hello_extensions->certificate_status_request.form ==
                CTLS_DATA_FORM_OPAQUE) {
                ctls_write_u16(buffer,
                               offset,
                               client_hello_extensions->certificate_status_request.opaque.
                               buffer_length);
                ctls_write_bytes(buffer,
                                 offset,
                                 client_hello_extensions->certificate_status_request.
                                 opaque.buffer_length,
                                 client_hello_extensions->certificate_status_request.
                                 opaque.buffer);
            }

            if (client_hello_extensions->certificate_status_request.form ==
                CTLS_DATA_FORM_PARSED) {
                ctls_size_t extension_length_offset = *offset;
                *offset += 2;
                ctls_write_u8(buffer,
                              offset,
                              client_hello_extensions->certificate_status_request.
                              status_request.certificate_status_type);
                ctls_write_u16(buffer,
                               offset,
                               client_hello_extensions->certificate_status_request.
                               status_request.ocsp_status_request.responder_id.
                               buffer_length);
                ctls_write_bytes(buffer,
                                 offset,
                                 client_hello_extensions->certificate_status_request.
                                 status_request.ocsp_status_request.responder_id.
                                 buffer_length,
                                 client_hello_extensions->certificate_status_request.
                                 status_request.ocsp_status_request.responder_id.buffer);
                ctls_write_u16(buffer,
                               offset,
                               client_hello_extensions->certificate_status_request.
                               status_request.ocsp_status_request.request_extensions.
                               buffer_length);
                ctls_write_bytes(buffer,
                                 offset,
                                 client_hello_extensions->certificate_status_request.
                                 status_request.ocsp_status_request.request_extensions.
                                 buffer_length,
                                 client_hello_extensions->certificate_status_request.
                                 status_request.ocsp_status_request.request_extensions.
                                 buffer);

                ctls_write_u16(buffer,
                               &extension_length_offset,
                               *offset - extension_length_offset);
            }
        }

        // supported groups
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SUPPORTED_GROUPS);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(client_hello_extensions->supported_groups.supported_group));
        ctls_write_u16(buffer,
                       offset,
                       client_hello_extensions->supported_groups.supported_group);

        // signature algorithms
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(client_hello_extensions->signature_algorithm.
                           signature_algorithm));
        ctls_write_u16(buffer,
                       offset,
                       client_hello_extensions->signature_algorithm.signature_algorithm);

        // use srtp
        // todo

        // heartbeat
        if (client_hello_extensions->heartbeat_mode !=
            CTLS_EXTN_HEARTBEAT_MODE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_HEARTBEAT);
            ctls_write_u8(buffer,
                          offset,
                          sizeof(client_hello_extensions->heartbeat_mode));
            ctls_write_u8(buffer, offset, client_hello_extensions->heartbeat_mode);
        }

        // alpn
        if (client_hello_extensions->alpn.form != CTLS_DATA_FORM_SENTINEL) {
            ctls_write_u16(buffer,
                           offset,
                           CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);

            if (client_hello_extensions->alpn.form == CTLS_DATA_FORM_OPAQUE) {
                ctls_write_u16(buffer,
                               offset,
                               client_hello_extensions->alpn.opaque.buffer_length);
                ctls_write_bytes(buffer,
                                 offset,
                                 client_hello_extensions->alpn.opaque.buffer_length,
                                 client_hello_extensions->alpn.opaque.buffer);
            }
            if (client_hello_extensions->alpn.form == CTLS_DATA_FORM_PARSED) {
                ctls_size_t extension_length_offset = *offset;

                ctls_size_t alpn_count =
                        sizeof(client_hello_extensions->alpn.alpn_list) / sizeof(
                            client_hello_extensions->alpn.alpn_list[0]);

                for (ctls_size_t alpn_index = 0; alpn_index < alpn_count; alpn_index++) {
                    ctls_write_u16(buffer,
                                   offset,
                                   client_hello_extensions->alpn.alpn_list[alpn_index].
                                   buffer_length);
                    ctls_write_bytes(buffer,
                                     offset,
                                     client_hello_extensions->alpn.alpn_list[alpn_index].
                                     buffer_length,
                                     client_hello_extensions->alpn.alpn_list[alpn_index].
                                     buffer);
                }
            }
        }

        // client certificate type
        if (client_hello_extensions->client_certificate_type ==
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(client_hello_extensions->client_certificate_type));
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->client_certificate_type);
        }


        // server certificate type
        if (client_hello_extensions->server_certificate_type ==
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(client_hello_extensions->server_certificate_type));
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->server_certificate_type);
        }

        // supported versions
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SUPPORTED_VERSIONS);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(client_hello_extensions->supported_versions.version));
        ctls_write_u16(buffer,
                       offset,
                       client_hello_extensions->supported_versions.version);


        // psk key exchange modes
        if (client_hello_extensions->psk_key_exchange_modes !=
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES);
            ctls_write_u8(buffer,
                          offset,
                          sizeof(client_hello_extensions->psk_key_exchange_modes));
            ctls_write_u8(buffer,
                          offset,
                          client_hello_extensions->psk_key_exchange_modes);
        }

        // signature algorithm cert
        if (client_hello_extensions->signature_algorithm_cert !=
            CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(client_hello_extensions->signature_algorithm_cert));
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->signature_algorithm_cert);
        }

        // key share
        if (client_hello_extensions->key_share_entity.form != CTLS_DATA_FORM_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->key_share_entity.key_share.
                           buffer_length);
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


    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_INVALID,
        . external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_server_hello_t const *
                                                server_hello_extensions,
                                                ctls_template_t const *template,
                                                ctls_wire_format_t wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        // supported versions
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SUPPORTED_VERSIONS);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(server_hello_extensions->supported_versions.version));
        ctls_write_u16(buffer,
                       offset,
                       server_hello_extensions->supported_versions.version);


        // key share
        if (server_hello_extensions->key_share_entity.form != CTLS_DATA_FORM_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
            ctls_write_u16(buffer,
                           offset,
                           server_hello_extensions->key_share_entity.key_share.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             server_hello_extensions->key_share_entity.key_share.
                             buffer_length,
                             server_hello_extensions->key_share_entity.key_share.buffer);
        }

        return (ctls_op_status_t){
            . source = CTLS_ERROR_SOURCE_INTERNAL,
            . code = CTLS_OP_STATUS_SUCCESS,
            . external_code = CTLS_OP_STATUS_SUCCESS,
        };
    }

    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_INVALID,
        . external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_server_hello_to_struct(
    ctls_extn_server_hello_t *server_hello_extensions,
    ctls_template_t const *template,
    ctls_hshk_buffer_t *hshk_buffer,
    ctls_hshk_data_t *hshk_data,
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_size_t buffer_size) {
    server_hello_extensions->supported_versions.form = CTLS_DATA_FORM_PARSED;
    server_hello_extensions->supported_versions.extension_type =
            CTLS_EXTN_TYPE_SUPPORTED_VERSIONS;
    server_hello_extensions->supported_versions.version = template->protocol_version;

    server_hello_extensions->key_share_entity.form = CTLS_DATA_FORM_PARSED;
    server_hello_extensions->key_share_entity.key_share.buffer_length = template->
            dhe_group.key_share_length;

    server_hello_extensions->key_share_entity.key_share.buffer = &hshk_buffer->buffer[
        hshk_buffer->buffer_length];
    ctls_read_bytes(&hshk_buffer->buffer[hshk_buffer->buffer_length],
                    template->dhe_group.key_share_length,
                    buffer,
                    offset);
    server_hello_extensions->key_share_entity.key_share.buffer_length = template->
            dhe_group.key_share_length;

    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_SUCCESS,
        . external_code = CTLS_OP_STATUS_SUCCESS,
    };
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



