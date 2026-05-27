
//
// Created by Sanjay Kumar Kumaravelan on 18/04/26.
//

#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/templates.h"
#include "ctls/bytes.h"

/*
 * struct {
 *  NamedType name_type;
 *  opaque name<1...2^16-1>;
 * }
 * enum {
 *  hostname(0), (255)
 *  } NameType
 *  struct {
 *      ServerName server_name_list<1...2^16-1>;
 *  } ServerNameList; // Extension Data
 */
ctls_op_status_t ctls_extn_server_name_deserialize(uint8_t *buffer,
                                                   ctls_size_t const *buffer_length,
                                                   ctls_data_form_t const form,
                                                   ctls_extn_server_name_t *server_name) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL(server_name);


    server_name->extension_type = CTLS_EXTN_TYPE_SERVER_NAME;
    server_name->form = form;

    if (form == CTLS_DATA_FORM_OPAQUE) {
        server_name->opaque.buffer_length = *buffer_length;
        server_name->opaque.buffer = buffer;
    }

    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;
        ctls_size_t server_name_list_index = offset;
        ctls_size_t server_name_list_length = ctls_read_u16(buffer, &offset);
        ctls_size_t server_name_list_absolute_length = offset + server_name_list_length;

        while (offset < server_name_list_absolute_length) {
            server_name->server_name_list[server_name_list_index].name_type =
                    ctls_read_u8(buffer, &server_name_list_index);
            server_name->server_name_list[server_name_list_index].server_name.
                    buffer_length = ctls_read_u16(buffer, &server_name_list_index);

            ctls_read_bytes(server_name->server_name_list[server_name_list_index].
                            server_name.buffer,
                            server_name->server_name_list[server_name_list_index].
                            server_name.buffer_length,
                            buffer,
                            &server_name_list_index);

            server_name_list_index++;
        }

        server_name->list_count = server_name_list_index;
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_extn_server_name_serialize(uint8_t *buffer,
                                                 ctls_size_t *offset,
                                                 ctls_extn_server_name_t const *
                                                 server_name) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);
    CTLS_CHECK_NULL(server_name);


    if (server_name->form != CTLS_DATA_FORM_OPAQUE && server_name->form !=
        CTLS_DATA_FORM_PARSED)
        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_INVALID,
            .external_code = CTLS_OP_STATUS_INVALID
        };

    ctls_write_u16(buffer, offset, server_name->extension_type);
    if (server_name->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, server_name->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         server_name->opaque.buffer_length,
                         server_name->opaque.buffer);
    }
    if (server_name->form == CTLS_DATA_FORM_PARSED) {
        if (server_name->list_count <= 0) {
            ctls_write_u16(buffer, offset, 0);
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_SUCCESS,
                .external_code = CTLS_OP_STATUS_SUCCESS,
            };
        }
        ctls_size_t extensions_length_offset = *offset;
        *offset += 2;

        for (ctls_size_t i = 0; i < server_name->list_count; i++) {
            ctls_write_u8(buffer, offset, server_name->server_name_list[i].name_type);
            ctls_write_u16(buffer,
                           offset,
                           server_name->server_name_list[i].server_name.buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             server_name->server_name_list[i].server_name.buffer_length,
                             server_name->server_name_list[i].server_name.buffer);
        }

        ctls_write_u16(buffer,
                       &extensions_length_offset,
                       *offset - extensions_length_offset);
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_extn_max_fragment_length_deserialize(
    ctls_max_fragment_length_t *source,
    ctls_max_fragment_length_t *max_fragment_length) {
    CTLS_CHECK_NULL(max_fragment_length);
    CTLS_CHECK_NULL(source);

    *max_fragment_length = *source;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}

ctls_op_status_t ctls_extn_max_fragment_length_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_max_fragment_length_t const *maximum_fragment_length) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);
    CTLS_CHECK_NULL(maximum_fragment_length);


    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH);
    ctls_write_u16(buffer, offset, sizeof(*maximum_fragment_length));
    ctls_write_u16(buffer, offset, *maximum_fragment_length);

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}


ctls_op_status_t ctls_extn_supported_groups_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    uint8_t is_raw_buffer,
    ctls_extn_supported_groups_t *supported_groups) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL(supported_groups);

    supported_groups->form = form;
    supported_groups->extension_type = CTLS_EXTN_TYPE_SUPPORTED_GROUPS;

    if (form == CTLS_DATA_FORM_OPAQUE && is_raw_buffer == 1) {
        supported_groups->opaque.buffer = buffer;
        supported_groups->opaque.buffer_length = *buffer_length;
    }

    ctls_size_t offset = 0;
    ctls_size_t extension_data_length = ctls_read_u16(buffer, &offset);
    ctls_size_t extension_data_index = 0;
    ctls_size_t extension_data_absolute_length = offset + extension_data_length;
    offset += 2;

    while (offset < extension_data_absolute_length && extension_data_index <
           CTLS_COUNT_SUPPORTED_GROUPS) {
        supported_groups->supported_group[extension_data_index] =
                ctls_read_u16(buffer, &offset);

        extension_data_index++;
    }
    supported_groups->list_count = extension_data_index;


    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}

ctls_op_status_t ctls_extn_supported_groups_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_supported_groups_t const *supported_groups) {
    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SUPPORTED_GROUPS);

    if (supported_groups->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, supported_groups->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         supported_groups->opaque.buffer_length,
                         supported_groups->opaque.buffer);
    }
    if (supported_groups->form == CTLS_DATA_FORM_PARSED) {
        if (supported_groups->list_count <= 0)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID
            };
        ctls_write_u16(buffer,
                       offset,
                       supported_groups->list_count * sizeof(supported_groups->
                           supported_group[0]));
        uint8_t extension_data_index = 0;
        while (extension_data_index < supported_groups->list_count) {
            ctls_write_u16(buffer,
                           offset,
                           supported_groups->supported_group[extension_data_index]);
        }
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_extn_signature_algorithm_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    uint8_t is_raw_buffer,
    ctls_extn_signature_algorithm_t *signature_algorithm) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL(signature_algorithm);

    signature_algorithm->form = form;
    signature_algorithm->extension_type = CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS;

    if (form == CTLS_DATA_FORM_OPAQUE && is_raw_buffer == 1) {
        signature_algorithm->opaque.buffer = buffer;
        signature_algorithm->opaque.buffer_length = *buffer_length;
    }

    ctls_size_t offset = 0;
    ctls_size_t extension_data_length = ctls_read_u16(buffer, &offset);
    ctls_size_t extension_data_index = 0;
    ctls_size_t extension_data_absolute_length = offset + extension_data_length;
    offset += 2;

    while (offset < extension_data_absolute_length && extension_data_index <
           CTLS_COUNT_SIGNATURE_ALGORITHM) {
        signature_algorithm->signature_algorithm[extension_data_index] =
                ctls_read_u16(buffer, &offset);

        extension_data_index++;
    }
    signature_algorithm->list_count = extension_data_index;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}

ctls_op_status_t ctls_extn_signature_algorithm_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm) {
    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS);
    if (signature_algorithm->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, signature_algorithm->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         signature_algorithm->opaque.buffer_length,
                         signature_algorithm->opaque.buffer);
    }
    if (signature_algorithm->form == CTLS_DATA_FORM_PARSED) {
        if (signature_algorithm->list_count <= 0)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID
            };

        ctls_write_u16(buffer,
                       offset,
                       signature_algorithm->list_count * sizeof(signature_algorithm->
                           signature_algorithm));
        uint8_t extension_data_index = 0;
        while (extension_data_index < signature_algorithm->list_count) {
            ctls_write_u16(buffer,
                           offset,
                           signature_algorithm->signature_algorithm[
                               extension_data_index]);
        }
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_extn_signature_algorithm_cert_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t const form,
    uint8_t const is_raw_buffer,
    ctls_extn_signature_algorithm_t *signature_algorithm_cert) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL(signature_algorithm_cert);

    signature_algorithm_cert->form = form;
    signature_algorithm_cert->extension_type = CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT;

    if (form == CTLS_DATA_FORM_OPAQUE && is_raw_buffer == 1) {
        signature_algorithm_cert->opaque.buffer = buffer;
        signature_algorithm_cert->opaque.buffer_length = *buffer_length;
    }

    ctls_size_t offset = 0;
    ctls_size_t extension_data_length = ctls_read_u16(buffer, &offset);
    ctls_size_t extension_data_index = 0;
    ctls_size_t extension_data_absolute_length = offset + extension_data_length;
    offset += 2;

    while (offset < extension_data_absolute_length && extension_data_index <
           CTLS_COUNT_SIGNATURE_ALGORITHM) {
        signature_algorithm_cert->signature_algorithm[extension_data_index] =
                ctls_read_u16(buffer, &offset);

        extension_data_index++;
    }
    signature_algorithm_cert->list_count = extension_data_index;


    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}

ctls_op_status_t ctls_extn_signature_algorithm_cert_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm_cert) {
    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT);
    if (signature_algorithm_cert->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, signature_algorithm_cert->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         signature_algorithm_cert->opaque.buffer_length,
                         signature_algorithm_cert->opaque.buffer);
    }
    if (signature_algorithm_cert->form == CTLS_DATA_FORM_PARSED) {
        if (signature_algorithm_cert->list_count <= 0)
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID
            };

        ctls_write_u16(buffer,
                       offset,
                       signature_algorithm_cert->list_count * sizeof(
                           signature_algorithm_cert->signature_algorithm[0]));
        uint8_t extension_data_index = 0;
        while (extension_data_index < signature_algorithm_cert->list_count) {
            ctls_write_u16(buffer,
                           offset,
                           signature_algorithm_cert->signature_algorithm[
                               extension_data_index]);
        }
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_extn_heartbeat_mode_deserialize(ctls_extn_heartbeat_mode_t *source,
                                                      ctls_extn_heartbeat_mode_t *
                                                      heartbeat_mode) {
    CTLS_CHECK_NULL(source);
    CTLS_CHECK_NULL(heartbeat_mode);

    *heartbeat_mode = *source;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS
    };
}

ctls_op_status_t ctls_extn_heartbeat_mode_serialize(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_extn_heartbeat_mode_t const *
                                                    heartbeat_mode) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(offset);
    CTLS_CHECK_NULL(heartbeat_mode);

    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_HEARTBEAT);
    ctls_write_u16(buffer, offset, sizeof(*heartbeat_mode));
    ctls_write_u8(buffer, offset, *heartbeat_mode);

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_extn_alpn_deserialize(uint8_t *buffer,
                                            ctls_size_t const *buffer_length,
                                            ctls_data_form_t const form,
                                            ctls_extn_alpn_t *alpn) {
    CTLS_CHECK_NULL(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL(alpn);

    alpn->form = form;
    alpn->extension_type = CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION;

    if (form == CTLS_DATA_FORM_OPAQUE) {
        alpn->opaque.buffer = buffer;
        alpn->opaque.buffer_length = *buffer_length;
    }
    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;
        ctls_size_t alpn_list_index = offset;
        ctls_size_t alpn_list_length = ctls_read_u16(buffer, &offset);
        ctls_size_t alpn_list_absolute_length = offset + alpn_list_length;

        while (offset < alpn_list_absolute_length) {
            alpn->alpn_list[alpn_list_index].protocol_name_length =
                    ctls_read_u8(buffer, &offset);
            ctls_read_bytes(alpn->alpn_list[alpn_list_index].protocol_name,
                            alpn->alpn_list[alpn_list_index].protocol_name_length,
                            buffer,
                            &offset);

            alpn_list_index++;
        }

        alpn->list_count = alpn_list_index;
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}

ctls_op_status_t ctls_extn_alpn_serialize(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          ctls_extn_alpn_t const *alpn) {
    ctls_write_u16(buffer, offset, alpn->extension_type);

    if (alpn->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, alpn->opaque.buffer_length);
        ctls_write_bytes(buffer, offset, alpn->opaque.buffer_length, alpn->opaque.buffer);
    }
    if (alpn->form == CTLS_DATA_FORM_PARSED) {
        if (alpn->list_count <= 0) {
            ctls_write_u16(buffer, offset, 0);
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_SUCCESS,
                .external_code = CTLS_OP_STATUS_SUCCESS,
            };
        }

        ctls_size_t extensions_length_offset = *offset;
        *offset += 2;

        for (uint8_t i = 0; i < alpn->list_count; i++) {
            ctls_write_u8(buffer, offset, alpn->alpn_list[i].protocol_name_length);
            ctls_write_bytes(buffer,
                             offset,
                             alpn->alpn_list[i].protocol_name_length,
                             alpn->alpn_list[i].protocol_name);
        }

        ctls_write_u16(buffer, offset, *offset - extensions_length_offset);
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID
    };
}



uint8_t ctls_expected_extensions_size_get(
    ctls_tmpl_expected_extensions_t const *expected_extensions) {
    return sizeof(*expected_extensions) / sizeof((*expected_extensions)[0]);
}

ctls_op_status_t ctls_extn_client_hello_create(
    ctls_extn_client_hello_t *client_hello_extensions) {
    ctls_template_t const *template = ctls_template_get();
    ctls_crypto_t const *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    uint8_t const size_of_expected_extensions =
            ctls_expected_extensions_size_get(&template->client_hello_extension.
                                              expected_extensions);

    // server_name
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->client_hello_extension.
                                           predefined_extensions.server_name. data,
                                           template->client_hello_extension.
                                           predefined_extensions.server_name. length)) {
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
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->client_hello_extension.
                                           predefined_extensions.
                                           certificate_status_request.data,
                                           template->client_hello_extension.
                                           predefined_extensions.
                                           certificate_status_request.length)) {
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
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->client_hello_extension.
                                           predefined_extensions.alpn.data,
                                           template->client_hello_extension.
                                           predefined_extensions.alpn. length)) {
        client_hello_extensions->alpn.form = CTLS_DATA_FORM_OPAQUE;
        client_hello_extensions->alpn.extension_type =
                CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
        client_hello_extensions->alpn.opaque.buffer = template->client_hello_extension.
                predefined_extensions.alpn.data;
        client_hello_extensions->alpn.opaque.buffer_length = template->
                client_hello_extension.predefined_extensions.alpn.length;
    }

    // signed_certificate_timestamp
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->client_hello_extension.
                                           predefined_extensions.
                                           signed_certificate_timestamp.data,
                                           template->client_hello_extension.
                                           predefined_extensions.
                                           signed_certificate_timestamp. length)) {
        client_hello_extensions->signed_certificate_timestamp.form =
                CTLS_DATA_FORM_OPAQUE;
        client_hello_extensions->signed_certificate_timestamp.extension_type =
                CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP;
        client_hello_extensions->signed_certificate_timestamp.opaque.buffer = template->
                client_hello_extension.predefined_extensions.signed_certificate_timestamp.
                data;
        client_hello_extensions->signed_certificate_timestamp.opaque.buffer_length =
                template->client_hello_extension.predefined_extensions.alpn.length;
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

    // certificate_authorities
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->client_hello_extension.
                                           predefined_extensions.certificate_authorities.
                                           data,
                                           template->client_hello_extension.
                                           predefined_extensions.certificate_authorities.
                                           length)) {
        client_hello_extensions->certificate_authorities.form = CTLS_DATA_FORM_OPAQUE;
        client_hello_extensions->certificate_authorities.extension_type =
                CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES;
        client_hello_extensions->certificate_authorities.opaque.buffer = template->
                client_hello_extension.predefined_extensions.certificate_authorities.data;
        client_hello_extensions->certificate_authorities.opaque.buffer_length = template->
                client_hello_extension.predefined_extensions.certificate_authorities.
                length;
    }

    // post_handshake_auth
    if (template->client_hello_extension.predefined_extensions.post_handshake_auth != 0) {
        client_hello_extensions->post_handshake_auth = template->client_hello_extension.
                predefined_extensions.post_handshake_auth;
    }


    // signature_algorithm_cert
    if (template->client_hello_extension.predefined_extensions.signature_algorithm_cert !=
        0) {
        client_hello_extensions->signature_algorithm_cert.form = CTLS_DATA_FORM_PARSED;
        client_hello_extensions->signature_algorithm_cert.extension_type =
                CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS;
        client_hello_extensions->signature_algorithm_cert.signature_algorithm = template->
                client_hello_extension.predefined_extensions.signature_algorithm_cert;
    }

    for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
        if (template->client_hello_extension.expected_extensions[i] !=
            CTLS_EXTN_TYPE_KEY_SHARE) continue;


        client_hello_extensions->key_share_entity.extension_type =
                CTLS_EXTN_TYPE_KEY_SHARE;
        client_hello_extensions->key_share_entity.form = CTLS_DATA_FORM_PARSED;

        ctls_op_status_t const result =
                ctls_ephemeral_public_key_generate(hshk_data->client_public_ephemeral_key,
                                                   &client_hello_extensions->
                                                   key_share_entity.key_share.
                                                   buffer_length);
        client_hello_extensions->key_share_entity.key_share.buffer = hshk_data->
                client_public_ephemeral_key;

        if (result.code != CTLS_OP_STATUS_SUCCESS) return result;
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t ctls_extn_client_hello_to_struct() {
}

ctls_op_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_client_hello_t const *
                                                client_hello_extensions,
                                                ctls_wire_format_t wire_format) {
    ctls_template_t const *template = ctls_template_get();
    CTLS_CHECK_NULL(template);


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

            if (client_hello_extensions->key_share_entity.form != CTLS_DATA_FORM_PARSED)
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_INVALID,
                    .external_code = CTLS_OP_STATUS_INVALID
                };

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
        // server_name
        if (client_hello_extensions->server_name.form == CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->server_name.extension_type);


            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->server_name.opaque.buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             client_hello_extensions->server_name.opaque.buffer_length,
                             client_hello_extensions->server_name.opaque.buffer);
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
        if (client_hello_extensions->certificate_status_request.form ==
            CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->certificate_status_request.
                           extension_type);


            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->certificate_status_request.opaque.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             client_hello_extensions->certificate_status_request.opaque.
                             buffer_length,
                             client_hello_extensions->certificate_status_request.opaque.
                             buffer);
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
        if (client_hello_extensions->alpn.form == CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer,
                           offset,
                           CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);


            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->alpn.opaque.buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             client_hello_extensions->alpn.opaque.buffer_length,
                             client_hello_extensions->alpn.opaque.buffer);
        }

        if (client_hello_extensions->signed_certificate_timestamp.form ==
            CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP);
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->signed_certificate_timestamp.opaque.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             client_hello_extensions->signed_certificate_timestamp.opaque.
                             buffer_length,
                             client_hello_extensions->signed_certificate_timestamp.opaque.
                             buffer);
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

        // certificate_authorities
        if (client_hello_extensions->certificate_authorities.form ==
            CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES);
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->certificate_authorities.opaque.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             client_hello_extensions->certificate_authorities.opaque.
                             buffer_length,
                             client_hello_extensions->certificate_authorities.opaque.
                             buffer);
        }

        // psk key exchange modes
        if (client_hello_extensions->psk_key_exchange_modes !=
            CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES);
            ctls_write_u8(buffer,
                          offset,
                          sizeof(client_hello_extensions->psk_key_exchange_modes));
            ctls_write_u8(buffer,
                          offset,
                          client_hello_extensions->psk_key_exchange_modes);
        }

        // signature algorithm cert
        if (client_hello_extensions->signature_algorithm_cert.form ==
            CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(client_hello_extensions->signature_algorithm_cert));
            ctls_write_u16(buffer,
                           offset,
                           client_hello_extensions->signature_algorithm_cert.
                           signature_algorithm);
        }

        // key share
        if (client_hello_extensions->key_share_entity.form == CTLS_DATA_FORM_PARSED) {
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
        } else
            return (ctls_op_status_t){
                . source = CTLS_ERROR_SOURCE_INTERNAL,
                . code = CTLS_OP_STATUS_INVALID,
                . external_code = CTLS_OP_STATUS_INVALID,
            };

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

ctls_op_status_t ctls_extn_server_hello_create(void) {
}

ctls_op_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                                ctls_size_t *offset,
                                                ctls_extn_server_hello_t const *
                                                server_hello_extensions,
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
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_size_t buffer_size) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hshk_data);

    server_hello_extensions->supported_versions.form = CTLS_DATA_FORM_PARSED;
    server_hello_extensions->supported_versions.extension_type =
            CTLS_EXTN_TYPE_SUPPORTED_VERSIONS;
    server_hello_extensions->supported_versions.version = template->protocol_version;

    server_hello_extensions->key_share_entity.form = CTLS_DATA_FORM_PARSED;
    server_hello_extensions->key_share_entity.key_share.buffer_length = template->
            dhe_group.key_share_length;

    ctls_read_bytes(hshk_data->server_public_ephemeral_key,
                    CTLS_SIZE_KEY_SHARE,
                    buffer,
                    offset);
    server_hello_extensions->key_share_entity.key_share.buffer = hshk_data->
            server_public_ephemeral_key;

    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_SUCCESS,
        . external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions) {
}

ctls_op_status_t ctls_extn_encrypted_extensions_to_struct(
    ctls_extn_encrypted_extensions_t *encrypted_extensions,
    ctls_size_t *offset) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(encrypted_extensions);
    CTLS_CHECK_NULL(offset);

    if (template->encrypted_extension.allow_additional) {
        *offset += 2;
    }

    // server_name
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->encrypted_extension.
                                           predefined_extensions.server_name. data,
                                           template->encrypted_extension.
                                           predefined_extensions.server_name. length)) {
        encrypted_extensions->server_name.form = CTLS_DATA_FORM_OPAQUE;
        encrypted_extensions->server_name.extension_type = CTLS_EXTN_TYPE_SERVER_NAME;
        encrypted_extensions->server_name.opaque.buffer_length = template->
                encrypted_extension.predefined_extensions.server_name.length;
        encrypted_extensions->server_name.opaque.buffer = template->encrypted_extension.
                predefined_extensions.server_name.data;
    }

    // max_fragment_length
    if (template->encrypted_extension.predefined_extensions.maximum_fragment_length ==
        0) {
        encrypted_extensions->maximum_fragment_length = template->encrypted_extension.
                predefined_extensions.maximum_fragment_length;
    }


    // supported_groups
    if (template->dhe_group.dhe_group != CTLS_EXTN_DHE_GROUP_SENTINEL) {
        encrypted_extensions->supported_groups.form = CTLS_DATA_FORM_PARSED;
        encrypted_extensions->supported_groups.extension_type =
                CTLS_EXTN_TYPE_SUPPORTED_GROUPS;
        encrypted_extensions->supported_groups.supported_group = template->dhe_group.
                dhe_group;
    }

    // heartbeat
    if (template->encrypted_extension.predefined_extensions.heartbeat_mode != 0) {
        encrypted_extensions->heartbeat_mode = template->encrypted_extension.
                predefined_extensions.heartbeat_mode;
    }

    // alpn
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->encrypted_extension.
                                           predefined_extensions.alpn.data,
                                           template->encrypted_extension.
                                           predefined_extensions.alpn. length)) {
        encrypted_extensions->alpn.form = CTLS_DATA_FORM_OPAQUE;
        encrypted_extensions->alpn.extension_type =
                CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
        encrypted_extensions->alpn.opaque.buffer = template->encrypted_extension.
                predefined_extensions.alpn.data;
        encrypted_extensions->alpn.opaque.buffer_length = template->encrypted_extension.
                predefined_extensions.alpn.length;
    }

    // client_certificate_type
    if (template->encrypted_extension.predefined_extensions.client_certificate_type !=
        0) {
        encrypted_extensions->client_certificate_type = template->encrypted_extension.
                predefined_extensions.client_certificate_type;
    }

    // server_certificate_type
    if (template->encrypted_extension.predefined_extensions.server_certificate_type !=
        0) {
        encrypted_extensions->server_certificate_type = template->encrypted_extension.
                predefined_extensions.server_certificate_type;
    }


    // no valid extensions in encrypted_extensions fit expected_extensions
    uint16_t size_of_expected_extensions =
            ctls_expected_extensions_size_get(&template->encrypted_extension.
                                              expected_extensions);

    if (size_of_expected_extensions != 0)
        return (ctls_op_status_t){
            . source = CTLS_ERROR_SOURCE_INTERNAL,
            . code = CTLS_OP_STATUS_INVALID,
            . external_code = CTLS_OP_STATUS_INVALID,
        };


    return (ctls_op_status_t){
        . source = CTLS_ERROR_SOURCE_INTERNAL,
        . code = CTLS_OP_STATUS_SUCCESS,
        . external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_extn_encrypted_extensions_to_wire(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_encrypted_extensions_t const *encrypted_extensions,
    ctls_wire_format_t wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        // server_name
        if (encrypted_extensions->server_name.form == CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer,
                           offset,
                           encrypted_extensions->server_name.extension_type);


            ctls_write_u16(buffer,
                           offset,
                           encrypted_extensions->server_name.opaque.buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             encrypted_extensions->server_name.opaque.buffer_length,
                             encrypted_extensions->server_name.opaque.buffer);
        }

        // max fragment length
        if (encrypted_extensions->maximum_fragment_length != 0) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(encrypted_extensions->maximum_fragment_length));
            ctls_write_u16(buffer, offset, encrypted_extensions->maximum_fragment_length);
        }


        // supported groups
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SUPPORTED_GROUPS);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(encrypted_extensions->supported_groups.supported_group));
        ctls_write_u16(buffer,
                       offset,
                       encrypted_extensions->supported_groups.supported_group);

        // heartbeat
        if (encrypted_extensions->heartbeat_mode != CTLS_EXTN_HEARTBEAT_MODE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_HEARTBEAT);
            ctls_write_u8(buffer, offset, sizeof(encrypted_extensions->heartbeat_mode));
            ctls_write_u8(buffer, offset, encrypted_extensions->heartbeat_mode);
        }

        // alpn
        if (encrypted_extensions->alpn.form == CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer,
                           offset,
                           CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);


            ctls_write_u16(buffer,
                           offset,
                           encrypted_extensions->alpn.opaque.buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             encrypted_extensions->alpn.opaque.buffer_length,
                             encrypted_extensions->alpn.opaque.buffer);
        }

        // client certificate type
        if (encrypted_extensions->client_certificate_type ==
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(encrypted_extensions->client_certificate_type));
            ctls_write_u16(buffer, offset, encrypted_extensions->client_certificate_type);
        }


        // server certificate type
        if (encrypted_extensions->server_certificate_type ==
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE);
            ctls_write_u16(buffer,
                           offset,
                           sizeof(encrypted_extensions->server_certificate_type));
            ctls_write_u16(buffer, offset, encrypted_extensions->server_certificate_type);
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

ctls_op_status_t ctls_extn_certificate_request_create(void) {
}

ctls_op_status_t ctls_extn_certificate_request_to_struct(
    ctls_extn_certificate_request_t *certificate_request_extensions,
    ctls_template_t const *template,
    ctls_size_t *offset) {
    CTLS_CHECK_NULL(certificate_request_extensions);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(offset);


    // certificate_status_request
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->certificate_request_extension.
                                           predefined_extensions.
                                           certificate_status_request.data,
                                           template->certificate_request_extension.
                                           predefined_extensions.
                                           certificate_status_request.length)) {
        certificate_request_extensions->certificate_status_request.form =
                CTLS_DATA_FORM_OPAQUE;
        certificate_request_extensions->certificate_status_request.extension_type =
                CTLS_EXTN_TYPE_STATUS_REQUEST;
        certificate_request_extensions->certificate_status_request.opaque.buffer_length =
                template->certificate_request_extension.predefined_extensions.
                certificate_status_request.length;
        certificate_request_extensions->certificate_status_request.opaque.buffer =
                template->certificate_request_extension.predefined_extensions.
                certificate_status_request.data;
    }

    // signature_algorithms
    if (template->signature_algorithm.signature_algorithm_type !=
        CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL) {
        certificate_request_extensions->signature_algorithm.form = CTLS_DATA_FORM_PARSED;
        certificate_request_extensions->signature_algorithm.extension_type =
                CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS;
        certificate_request_extensions->signature_algorithm.signature_algorithm = template
                ->signature_algorithm.signature_algorithm_type;
    }

    // signed_certificate_timestamp
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->certificate_request_extension.
                                           predefined_extensions.
                                           signed_certificate_timestamp.data,
                                           template->certificate_request_extension.
                                           predefined_extensions.
                                           signed_certificate_timestamp. length)) {
        certificate_request_extensions->signed_certificate_timestamp.form =
                CTLS_DATA_FORM_OPAQUE;
        certificate_request_extensions->signed_certificate_timestamp.extension_type =
                CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP;
        certificate_request_extensions->signed_certificate_timestamp.opaque.buffer =
                template->client_hello_extension.predefined_extensions.
                signed_certificate_timestamp.data;
        certificate_request_extensions->signed_certificate_timestamp.opaque.buffer_length
                = template->client_hello_extension.predefined_extensions.alpn.length;
    }

    // certificate_authorities
    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(template->certificate_request_extension.
                                           predefined_extensions.certificate_authorities.
                                           data,
                                           template->certificate_request_extension.
                                           predefined_extensions.certificate_authorities.
                                           length)) {
        certificate_request_extensions->certificate_authorities.form =
                CTLS_DATA_FORM_OPAQUE;
        certificate_request_extensions->certificate_authorities.extension_type =
                CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES;
        certificate_request_extensions->certificate_authorities.opaque.buffer = template->
                certificate_request_extension.predefined_extensions.
                certificate_authorities.data;
        certificate_request_extensions->certificate_authorities.opaque.buffer_length =
                template->certificate_request_extension.predefined_extensions.
                certificate_authorities.length;
    }

    // signature_algorithm_cert
    if (template->certificate_request_extension.predefined_extensions.
        signature_algorithm_cert != 0) {
        certificate_request_extensions->signature_algorithm_cert = template->
                client_hello_extension.predefined_extensions.signature_algorithm_cert;
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_extn_certificate_request_to_wire(uint8_t *buffer,
                                                       ctls_size_t *offset,
                                                       ctls_extn_certificate_request_t
                                                       const *certificate_request,
                                                       ctls_wire_format_t wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        // certificate status request
        if (certificate_request->certificate_status_request.form ==
            CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer,
                           offset,
                           certificate_request->certificate_status_request.
                           extension_type);


            ctls_write_u16(buffer,
                           offset,
                           certificate_request->certificate_status_request.opaque.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             certificate_request->certificate_status_request.opaque.
                             buffer_length,
                             certificate_request->certificate_status_request.opaque.
                             buffer);
        }


        // signature algorithms
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(certificate_request->signature_algorithm.
                           signature_algorithm));
        ctls_write_u16(buffer,
                       offset,
                       certificate_request->signature_algorithm.signature_algorithm);

        // signed_certificate_timestamp
        if (certificate_request->signed_certificate_timestamp.form ==
            CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP);
            ctls_write_u16(buffer,
                           offset,
                           certificate_request->signed_certificate_timestamp.opaque.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             certificate_request->signed_certificate_timestamp.opaque.
                             buffer_length,
                             certificate_request->signed_certificate_timestamp.opaque.
                             buffer);
        }

        // certificate_authorities
        if (certificate_request->certificate_authorities.form == CTLS_DATA_FORM_OPAQUE) {
            ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES);
            ctls_write_u16(buffer,
                           offset,
                           certificate_request->certificate_authorities.opaque.
                           buffer_length);
            ctls_write_bytes(buffer,
                             offset,
                             certificate_request->certificate_authorities.opaque.
                             buffer_length,
                             certificate_request->certificate_authorities.opaque.buffer);
        }

        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_SUCCESS,
            .external_code = CTLS_OP_STATUS_SUCCESS,
        };
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}
