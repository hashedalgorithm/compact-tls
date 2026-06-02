
//
// Created by Sanjay Kumar Kumaravelan on 18/04/26.
//

#include <string.h>
#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/templates.h"
#include "ctls/bytes.h"

ctls_status_t ctls_extn_enum_deserialize(void const *source,
                                         void *destination,
                                         ctls_helper_is_one_byte_t const isOneByte) {
    CTLS_CHECK_NULL(source);
    CTLS_CHECK_NULL(destination);

    if (isOneByte != CTLS_HELPER_IS_ONE_BYTE && isOneByte != CTLS_HELPER_IS_TWO_BYTE)
        return CTLS_STATUS_EXTN_INVALID_SIZE_FLAG;

    memcpy(destination, source, isOneByte == CTLS_HELPER_IS_ONE_BYTE ? 1 : 2);

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_enum_serialize(uint8_t *buffer,
                                       ctls_size_t *offset,
                                       ctls_extn_type_t const extn_type,
                                       ctls_helper_is_one_byte_t const isOneByte,
                                       uint16_t const value) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (isOneByte != CTLS_HELPER_IS_ONE_BYTE && isOneByte != CTLS_HELPER_IS_TWO_BYTE)
        return CTLS_STATUS_EXTN_INVALID_SIZE_FLAG;

    ctls_write_u16(buffer, offset, extn_type);
    ctls_write_u16(buffer, offset, isOneByte == CTLS_HELPER_IS_ONE_BYTE ? 1 : 2);

    if (isOneByte == CTLS_HELPER_IS_ONE_BYTE) {
        ctls_write_u8(buffer, offset, value);
    } else {
        ctls_write_u16(buffer, offset, value);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_is_initialized(ctls_extn_type_t const extn_type,
                                       ctls_hsmg_type_t const hsmg_type,
                                       uint8_t *is_initialized) {
    ctls_template_t const *template = ctls_template_get();
    CTLS_CHECK_NULL(template);

    ctls_tmpl_predefined_extensions_t const *predefined_extensions;
    switch (hsmg_type) {
        case CTLS_HSMG_TYPE_CLIENT_HELLO:
            predefined_extensions = &template->client_hello_extension.
                    predefined_extensions;
            break;
        case CTLS_HSMG_TYPE_SERVER_HELLO:
            predefined_extensions = &template->server_hello_extension.
                    predefined_extensions;
            break;
        case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS:
            predefined_extensions = &template->encrypted_extension.predefined_extensions;
            break;
        case CTLS_HSMG_TYPE_CERTIFICATE_REQUEST:
            predefined_extensions = &template->certificate_request_extension.
                    predefined_extensions;
            break;
        default: return CTLS_STATUS_EXTN_UNKNOWN_MSG_TYPE;
    }

    CTLS_CHECK_NULL(predefined_extensions);
    switch (extn_type) {
        case CTLS_EXTN_TYPE_SERVER_NAME:
            *is_initialized =
                    CTLS_IS_TEMPLATE_BYTES_INITIALIZED(predefined_extensions->server_name.
                                                       data,
                                                       predefined_extensions->server_name.
                                                       length);
            break;
        case CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH:
            *is_initialized = predefined_extensions->maximum_fragment_length != 0;
            break;
        case CTLS_EXTN_TYPE_STATUS_REQUEST:
            *is_initialized =
                    CTLS_IS_TEMPLATE_BYTES_INITIALIZED(predefined_extensions->
                                                       certificate_status_request.data,
                                                       predefined_extensions->
                                                       certificate_status_request.length);
            break;
        case CTLS_EXTN_TYPE_SUPPORTED_GROUPS:
            *is_initialized = template->dhe_group.dhe_group !=
                              CTLS_EXTN_DHE_GROUP_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS:
            *is_initialized = template->signature_algorithm.signature_algorithm_type !=
                              CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_HEARTBEAT:
            *is_initialized = predefined_extensions->heartbeat_mode !=
                              CTLS_EXTN_HEARTBEAT_MODE_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            *is_initialized =
                    CTLS_IS_TEMPLATE_BYTES_INITIALIZED(predefined_extensions->alpn.data,
                                                       predefined_extensions->alpn.
                                                       length);
            break;
        case CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP:
            *is_initialized =
                    CTLS_IS_TEMPLATE_BYTES_INITIALIZED(predefined_extensions->
                                                       signed_certificate_timestamp.data,
                                                       predefined_extensions->
                                                       signed_certificate_timestamp.
                                                       length);
            break;
        case CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE:
            *is_initialized = predefined_extensions->client_certificate_type !=
                              CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE:
            *is_initialized = predefined_extensions->server_certificate_type !=
                              CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_SUPPORTED_VERSIONS:
            *is_initialized = template->protocol_version !=
                              CTLS_HSMG_PROTOCOL_VERSION_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES:
            *is_initialized = predefined_extensions->psk_key_exchange_modes !=
                              CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_SENTINEL;
            break;
        case CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES:
            *is_initialized =
                    CTLS_IS_TEMPLATE_BYTES_INITIALIZED(predefined_extensions->
                                                       certificate_authorities.data,
                                                       predefined_extensions->
                                                       certificate_authorities.length);
            break;
        case CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH:
            *is_initialized = predefined_extensions->post_handshake_auth != 0;
            break;
        case CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT:
            *is_initialized = predefined_extensions->signature_algorithm_cert !=
                              CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL;
            break;
        default:
            return CTLS_STATUS_EXTN_UNKNOWN_TYPE;
    }
    return CTLS_STATUS_SUCCESS;
}


ctls_status_t ctls_extn_server_name_deserialize(uint8_t *buffer,
                                                ctls_size_t const *buffer_length,
                                                ctls_data_form_t const form,
                                                ctls_extn_server_name_t *server_name) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL_STRUCT(server_name);

    server_name->form = form;

    if (form == CTLS_DATA_FORM_OPAQUE) {
        server_name->opaque.buffer_length = *buffer_length;
        server_name->opaque.buffer = buffer;
    }

    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;
        ctls_size_t server_name_list_index = 0;
        ctls_size_t server_name_list_length = ctls_read_u16(buffer, &offset);
        ctls_size_t server_name_list_absolute_length = offset + server_name_list_length;

        while (offset < server_name_list_absolute_length) {
            server_name->server_name_list[server_name_list_index].name_type =
                    ctls_read_u8(buffer, &offset);
            server_name->server_name_list[server_name_list_index].server_name.
                    buffer_length = ctls_read_u16(buffer, &offset);
            ctls_read_bytes(server_name->server_name_list[server_name_list_index].
                            server_name.buffer,
                            server_name->server_name_list[server_name_list_index].
                            server_name.buffer_length,
                            buffer,
                            &offset);
            server_name_list_index++;
        }

        server_name->list_count = server_name_list_index;
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_server_name_serialize(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_extn_server_name_t const *server_name) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(server_name);

    if (server_name->form != CTLS_DATA_FORM_OPAQUE && server_name->form !=
        CTLS_DATA_FORM_PARSED) return CTLS_STATUS_EXTN_INVALID_FORM;

    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SERVER_NAME);
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
            return CTLS_STATUS_SUCCESS;
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
                       *offset - extensions_length_offset - 2);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_max_fragment_length_deserialize(
    ctls_extn_max_fragment_length_t const *source,
    ctls_extn_max_fragment_length_t *max_fragment_length) {
    return ctls_extn_enum_deserialize(source,
                                      max_fragment_length,
                                      CTLS_HELPER_IS_ONE_BYTE);
}

ctls_status_t ctls_extn_max_fragment_length_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_max_fragment_length_t const *max_fragment_length) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH,
                                    CTLS_HELPER_IS_ONE_BYTE,
                                    *max_fragment_length);
}

ctls_status_t ctls_extn_certificate_status_request_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_certificate_status_request_t *certificate_status_request) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL_STRUCT(certificate_status_request);

    certificate_status_request->form = form;

    if (form == CTLS_DATA_FORM_OPAQUE) {
        certificate_status_request->opaque.buffer = buffer;
        certificate_status_request->opaque.buffer_length = *buffer_length;
    }
    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;

        certificate_status_request->status_request.certificate_status_type =
                ctls_read_u8(buffer, &offset);

        if (certificate_status_request->status_request.certificate_status_type !=
            CTLS_EXTN_CERTIFICATE_STATUS_TYPE_OSCP) return
                CTLS_STATUS_EXTN_INVALID_STATUS_TYPE;

        offset += 2;
        offset += 2;
        certificate_status_request->status_request.ocsp_status_request.responder_id =
                ctls_read_u8(buffer, &offset);
        offset += 2;
        certificate_status_request->status_request.ocsp_status_request.request_extensions
                = ctls_read_u8(buffer, &offset);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_certificate_status_request_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_status_request_t const *certificate_status_request) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_status_request);

    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_STATUS_REQUEST);
    if (certificate_status_request->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, certificate_status_request->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         certificate_status_request->opaque.buffer_length,
                         certificate_status_request->opaque.buffer);
    }
    if (certificate_status_request->form == CTLS_DATA_FORM_PARSED) {
        ctls_write_u8(buffer,
                      offset,
                      certificate_status_request->status_request.certificate_status_type);

        ctls_size_t responder_list_length_offset = *offset;
        *offset += 2;

        ctls_write_u16(buffer,
                       offset,
                       sizeof(certificate_status_request->status_request.
                           ocsp_status_request.responder_id));
        ctls_write_u8(buffer,
                      offset,
                      certificate_status_request->status_request.ocsp_status_request.
                      responder_id);
        ctls_write_u8(buffer,
                      offset,
                      certificate_status_request->status_request.ocsp_status_request.
                      request_extensions);

        ctls_write_u16(buffer,
                       &responder_list_length_offset,
                       *offset - responder_list_length_offset);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_supported_groups_deserialize(
    ctls_extn_supported_group_t const *source,
    ctls_extn_supported_group_t *supported_group) {
    return ctls_extn_enum_deserialize(source, supported_group, CTLS_HELPER_IS_TWO_BYTE);
}

ctls_status_t ctls_extn_supported_groups_serialize(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_extn_supported_group_t const *
                                                   supported_groups) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_SUPPORTED_GROUPS,
                                    CTLS_HELPER_IS_TWO_BYTE,
                                    *supported_groups);
}

ctls_status_t ctls_extn_signature_algorithm_deserialize(
    ctls_extn_signature_algorithm_t const *source,
    ctls_extn_signature_algorithm_t *signature_algorithm) {
    return ctls_extn_enum_deserialize(source,
                                      signature_algorithm,
                                      CTLS_HELPER_IS_TWO_BYTE);
}

ctls_status_t ctls_extn_signature_algorithm_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS,
                                    CTLS_HELPER_IS_TWO_BYTE,
                                    *signature_algorithm);
}

ctls_status_t ctls_extn_signature_algorithm_cert_deserialize(
    ctls_extn_signature_algorithm_t const *source,
    ctls_extn_signature_algorithm_t *signature_algorithm_cert) {
    return ctls_extn_enum_deserialize(source,
                                      signature_algorithm_cert,
                                      CTLS_HELPER_IS_TWO_BYTE);
}

ctls_status_t ctls_extn_signature_algorithm_cert_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm_cert) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT,
                                    CTLS_HELPER_IS_TWO_BYTE,
                                    *signature_algorithm_cert);
}

ctls_status_t ctls_extn_heartbeat_mode_deserialize(
    ctls_extn_heartbeat_mode_t const *source,
    ctls_extn_heartbeat_mode_t *heartbeat_mode) {
    return ctls_extn_enum_deserialize(source, heartbeat_mode, CTLS_HELPER_IS_ONE_BYTE);
}

ctls_status_t ctls_extn_heartbeat_mode_serialize(uint8_t *buffer,
                                                 ctls_size_t *offset,
                                                 ctls_extn_heartbeat_mode_t const *
                                                 heartbeat_mode) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_HEARTBEAT,
                                    CTLS_HELPER_IS_ONE_BYTE,
                                    *heartbeat_mode);
}

ctls_status_t ctls_extn_alpn_deserialize(uint8_t *buffer,
                                         ctls_size_t const *buffer_length,
                                         ctls_data_form_t const form,
                                         ctls_extn_alpn_t *alpn) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL_STRUCT(alpn);

    alpn->form = form;

    if (form == CTLS_DATA_FORM_OPAQUE) {
        alpn->opaque.buffer = buffer;
        alpn->opaque.buffer_length = *buffer_length;
    }
    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;
        ctls_size_t alpn_list_index = 0;
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

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_alpn_serialize(uint8_t *buffer,
                                       ctls_size_t *offset,
                                       ctls_extn_alpn_t const *alpn) {
    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);

    if (alpn->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, alpn->opaque.buffer_length);
        ctls_write_bytes(buffer, offset, alpn->opaque.buffer_length, alpn->opaque.buffer);
    }
    if (alpn->form == CTLS_DATA_FORM_PARSED) {
        if (alpn->list_count <= 0) {
            ctls_write_u16(buffer, offset, 0);
            return CTLS_STATUS_SUCCESS;
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

        ctls_write_u16(buffer,
                       &extensions_length_offset,
                       *offset - extensions_length_offset - 2);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_signed_certificate_timestamp_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_signed_certificate_timestamp_t *signed_certificate_timestamp) {
    signed_certificate_timestamp->extension_type =
            CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP;
    signed_certificate_timestamp->form = form;

    if (form == CTLS_DATA_FORM_OPAQUE) {
        signed_certificate_timestamp->opaque.buffer = buffer;
        signed_certificate_timestamp->opaque.buffer_length = *buffer_length;
    }
    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;
        signed_certificate_timestamp->signed_certificate_timestamp.sct_version =
                ctls_read_u8(buffer, &offset);
        ctls_read_bytes(signed_certificate_timestamp->signed_certificate_timestamp.log_id,
                        CTLS_SIZE_SCT_LOG_ID,
                        buffer,
                        &offset);
        signed_certificate_timestamp->signed_certificate_timestamp.timestamp =
                ctls_read_u64(buffer, &offset);
        signed_certificate_timestamp->signed_certificate_timestamp.extensions =
                ctls_read_u8(buffer, &offset);
        signed_certificate_timestamp->signed_certificate_timestamp.signature_algorithm =
                ctls_read_u16(buffer, &offset);
        signed_certificate_timestamp->signed_certificate_timestamp.certificate.
                buffer_length = ctls_read_u16(buffer, &offset);
        ctls_read_bytes(signed_certificate_timestamp->signed_certificate_timestamp.
                        certificate.buffer,
                        signed_certificate_timestamp->signed_certificate_timestamp.
                        certificate.buffer_length,
                        buffer,
                        &offset);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_signed_certificate_timestamp_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signed_certificate_timestamp_t const *signed_certificate_timestamp) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(signed_certificate_timestamp);

    if (signed_certificate_timestamp->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP);
        ctls_write_u16(buffer,
                       offset,
                       signed_certificate_timestamp->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         signed_certificate_timestamp->opaque.buffer_length,
                         signed_certificate_timestamp->opaque.buffer);
    }
    if (signed_certificate_timestamp->form == CTLS_DATA_FORM_PARSED) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP);

        ctls_size_t length_offset = *offset;
        *offset += 2;

        ctls_write_u8(buffer,
                      offset,
                      signed_certificate_timestamp->signed_certificate_timestamp.
                      sct_version);
        ctls_write_bytes(buffer,
                         offset,
                         CTLS_SIZE_SCT_LOG_ID,
                         signed_certificate_timestamp->signed_certificate_timestamp.
                         log_id);
        ctls_write_u64(buffer,
                       offset,
                       signed_certificate_timestamp->signed_certificate_timestamp.
                       timestamp);
        ctls_write_u8(buffer,
                      offset,
                      signed_certificate_timestamp->signed_certificate_timestamp.
                      extensions);
        ctls_write_u16(buffer,
                       offset,
                       signed_certificate_timestamp->signed_certificate_timestamp.
                       signature_algorithm);
        ctls_write_bytes(buffer,
                         offset,
                         signed_certificate_timestamp->signed_certificate_timestamp.
                         certificate.buffer_length,
                         signed_certificate_timestamp->signed_certificate_timestamp.
                         certificate.buffer);

        ctls_write_u16(buffer, &length_offset, *offset - length_offset - 2);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_client_certificate_type_deserialize(
    ctls_extn_client_certificate_type_t const *source,
    ctls_extn_client_certificate_type_t *client_certificate_type) {
    return ctls_extn_enum_deserialize(source,
                                      client_certificate_type,
                                      CTLS_HELPER_IS_ONE_BYTE);
}

ctls_status_t ctls_extn_client_certificate_type_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_client_certificate_type_t const *client_certificate_type) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE,
                                    CTLS_HELPER_IS_ONE_BYTE,
                                    *client_certificate_type);
}

ctls_status_t ctls_extn_server_certificate_type_deserialize(
    ctls_extn_server_certificate_type_t const *source,
    ctls_extn_server_certificate_type_t *server_certificate_type) {
    return ctls_extn_enum_deserialize(source,
                                      server_certificate_type,
                                      CTLS_HELPER_IS_ONE_BYTE);
}

ctls_status_t ctls_extn_server_certificate_type_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_server_certificate_type_t const *server_certificate_type) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE,
                                    CTLS_HELPER_IS_ONE_BYTE,
                                    *server_certificate_type);
}

ctls_status_t ctls_extn_supported_versions_deserialize(
    ctls_extn_supported_version_t const *source,
    ctls_extn_supported_version_t *supported_versions) {
    return ctls_extn_enum_deserialize(source,
                                      supported_versions,
                                      CTLS_HELPER_IS_TWO_BYTE);
}

ctls_status_t ctls_extn_supported_versions_serialize(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_extn_supported_version_t const *
                                                     supported_versions) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_SUPPORTED_VERSIONS,
                                    CTLS_HELPER_IS_TWO_BYTE,
                                    *supported_versions);
}

ctls_status_t ctls_extn_psk_key_exchange_modes_deserialize(
    ctls_extn_psk_key_exchange_mode_t const *source,
    ctls_extn_psk_key_exchange_mode_t *psk_key_exchange_modes) {
    return ctls_extn_enum_deserialize(source,
                                      psk_key_exchange_modes,
                                      CTLS_HELPER_IS_ONE_BYTE);
}

ctls_status_t ctls_extn_psk_key_exchange_modes_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_psk_key_exchange_mode_t const *psk_key_exchange_modes) {
    return ctls_extn_enum_serialize(buffer,
                                    offset,
                                    CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES,
                                    CTLS_HELPER_IS_ONE_BYTE,
                                    *psk_key_exchange_modes);
}

ctls_status_t ctls_extn_certificate_authorities_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t const form,
    ctls_extn_certificate_authorities_t *certificate_authorities) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL_STRUCT(certificate_authorities);

    if (form == CTLS_DATA_FORM_OPAQUE) {
        certificate_authorities->opaque.buffer = buffer;
        certificate_authorities->opaque.buffer_length = *buffer_length;
    }
    if (form == CTLS_DATA_FORM_PARSED) {
        ctls_size_t offset = 0;
        certificate_authorities->distinguished_name_length =
                ctls_read_u16(buffer, &offset);
        ctls_read_bytes(certificate_authorities->distinguished_name,
                        certificate_authorities->distinguished_name_length,
                        buffer,
                        &offset);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_certificate_authorities_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_authorities_t const *certificate_authorities) {
    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES);
    if (certificate_authorities->form == CTLS_DATA_FORM_OPAQUE) {
        ctls_write_u16(buffer, offset, certificate_authorities->opaque.buffer_length);
        ctls_write_bytes(buffer,
                         offset,
                         certificate_authorities->opaque.buffer_length,
                         certificate_authorities->opaque.buffer);
    }
    if (certificate_authorities->form == CTLS_DATA_FORM_PARSED) {
        ctls_write_u16(buffer,
                       offset,
                       certificate_authorities->distinguished_name_length);
        ctls_write_bytes(buffer,
                         offset,
                         certificate_authorities->distinguished_name_length,
                         certificate_authorities->distinguished_name);
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_post_handshake_auth_deserialize(
    ctls_extn_post_handshake_auth_t const *source,
    ctls_extn_post_handshake_auth_t *post_handshake_auth) {
    return ctls_extn_enum_deserialize(source,
                                      post_handshake_auth,
                                      CTLS_HELPER_IS_ONE_BYTE);
}

ctls_status_t ctls_extn_post_handshake_auth_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_post_handshake_auth_t const *post_handshake_auth) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(post_handshake_auth);

    if (!*post_handshake_auth) return CTLS_STATUS_SUCCESS;

    ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH);
    ctls_write_u16(buffer, offset, 0);

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_key_share_deserialize(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_helper_entity_ownership_t const
                                              entity_ownership,
                                              ctls_extn_key_share_t *key_share) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(key_share);
    CTLS_CHECK_NULL(hshk_data);

    if (entity_ownership != CTLS_HELPER_ENTITY_OWNERSHIP_CLIENT && entity_ownership !=
        CTLS_HELPER_ENTITY_OWNERSHIP_SERVER) return
            CTLS_STATUS_EXTN_INVALID_ENTITY_OWNERSHIP;

    ctls_read_bytes(entity_ownership == CTLS_HELPER_ENTITY_OWNERSHIP_SERVER
                        ? hshk_data->server_public_ephemeral_key
                        : hshk_data->client_public_ephemeral_key,
                    CTLS_SIZE_KEY_SHARE,
                    buffer,
                    offset);
    *key_share = entity_ownership == CTLS_HELPER_ENTITY_OWNERSHIP_SERVER
                     ? hshk_data->server_public_ephemeral_key
                     : hshk_data->client_public_ephemeral_key;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_key_share_serialize(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_wire_format_t const wire_format,
                                            ctls_extn_key_share_t key_share) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(key_share);

    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
    }

    ctls_write_u16(buffer, offset, CTLS_SIZE_KEY_SHARE);
    ctls_write_bytes(buffer, offset, CTLS_SIZE_KEY_SHARE, key_share);

    return CTLS_STATUS_SUCCESS;
}


uint8_t ctls_expected_extensions_size_get(
    ctls_tmpl_expected_extensions_t const *expected_extensions) {
    return sizeof(*expected_extensions) / sizeof((*expected_extensions)[0]);
}

ctls_status_t ctls_extn_client_hello_create(
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
    uint8_t is_initialized = 0;

    ctls_status_t result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SERVER_NAME,
                                                    CTLS_HSMG_TYPE_CLIENT_HELLO,
                                                    &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (is_initialized) {
        result = ctls_extn_server_name_deserialize(template->client_hello_extension.
                                                   predefined_extensions.server_name.data,
                                                   &template->client_hello_extension.
                                                   predefined_extensions.server_name.
                                                   length,
                                                   CTLS_DATA_FORM_OPAQUE,
                                                   &client_hello_extensions->server_name);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (is_initialized) {
        result = ctls_extn_max_fragment_length_deserialize(&template->
                                                           client_hello_extension.
                                                           predefined_extensions.
                                                           maximum_fragment_length,
                                                           &client_hello_extensions->
                                                           maximum_fragment_length);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_STATUS_REQUEST,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_certificate_status_request_deserialize(template->
            client_hello_extension.predefined_extensions.certificate_status_request.
            data,
            &template->client_hello_extension.predefined_extensions.
            certificate_status_request.length,
            CTLS_DATA_FORM_OPAQUE,
            &client_hello_extensions->certificate_status_request);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SUPPORTED_GROUPS,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_supported_groups_deserialize(&template->dhe_group.dhe_group,
                                                        &client_hello_extensions->
                                                        supported_groups);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_signature_algorithm_deserialize(&template->signature_algorithm.
                                                           signature_algorithm_type,
                                                           &client_hello_extensions->
                                                           signature_algorithm);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_HEARTBEAT,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_heartbeat_mode_deserialize(&template->client_hello_extension.
                                                      predefined_extensions.
                                                      heartbeat_mode,
                                                      &client_hello_extensions->
                                                      heartbeat_mode);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result =
            ctls_extn_is_initialized(CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                     CTLS_HSMG_TYPE_CLIENT_HELLO,
                                     &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_alpn_deserialize(template->client_hello_extension.
                                            predefined_extensions.alpn.data,
                                            &template->client_hello_extension.
                                            predefined_extensions.alpn.length,
                                            CTLS_DATA_FORM_OPAQUE,
                                            &client_hello_extensions->alpn);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_signed_certificate_timestamp_deserialize(template->
            client_hello_extension.predefined_extensions.signed_certificate_timestamp
            .data,
            &template->client_hello_extension.predefined_extensions.
            signed_certificate_timestamp.length,
            CTLS_DATA_FORM_OPAQUE,
            &client_hello_extensions->signed_certificate_timestamp);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_client_certificate_type_deserialize(&template->
            client_hello_extension.predefined_extensions.client_certificate_type,
            &client_hello_extensions->client_certificate_type);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_server_certificate_type_deserialize(&template->
            client_hello_extension.predefined_extensions.server_certificate_type,
            &client_hello_extensions->server_certificate_type);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SUPPORTED_VERSIONS,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_supported_versions_deserialize(&template->protocol_version,
                                                          &client_hello_extensions->
                                                          supported_versions);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_psk_key_exchange_modes_deserialize(&template->
            client_hello_extension.predefined_extensions.psk_key_exchange_modes,
            &client_hello_extensions->psk_key_exchange_modes);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_certificate_authorities_deserialize(template->
            client_hello_extension.predefined_extensions.certificate_authorities.
            data,
            &template->client_hello_extension.predefined_extensions.
            certificate_authorities.length,
            CTLS_DATA_FORM_OPAQUE,
            &client_hello_extensions->certificate_authorities);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_post_handshake_auth_deserialize(&template->
                                                           client_hello_extension.
                                                           predefined_extensions.
                                                           post_handshake_auth,
                                                           &client_hello_extensions->
                                                           post_handshake_auth);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT,
                                      CTLS_HSMG_TYPE_CLIENT_HELLO,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_signature_algorithm_cert_deserialize(&template->
            client_hello_extension.predefined_extensions.signature_algorithm_cert,
            &client_hello_extensions->signature_algorithm_cert);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
        if (template->client_hello_extension.expected_extensions[i] !=
            CTLS_EXTN_TYPE_KEY_SHARE) continue;

        ctls_size_t bytes_written = CTLS_SIZE_KEY_SHARE;
        result = ctls_ephemeral_public_key_generate(hshk_data->
                                                    client_public_ephemeral_key,
                                                    &bytes_written);
        if (result != CTLS_STATUS_SUCCESS) return result;

        client_hello_extensions->key_share_entity = hshk_data->
                client_public_ephemeral_key;
    }

    return CTLS_STATUS_SUCCESS;
}


ctls_status_t ctls_extn_client_hello_to_struct() {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
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
        for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
            if (template->client_hello_extension.expected_extensions[i] ==
                CTLS_EXTN_TYPE_KEY_SHARE) {
                ctls_size_t key_share_start = *offset;
                if (template->dhe_group.key_share_length == 0) {
                    ctls_write_u16(buffer, &key_share_start, CTLS_SIZE_KEY_SHARE);
                }
                ctls_write_bytes(buffer,
                                 offset,
                                 CTLS_SIZE_KEY_SHARE,
                                 client_hello_extensions->key_share_entity);
            }
        }
        return CTLS_STATUS_SUCCESS;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        if (client_hello_extensions->server_name.form != CTLS_DATA_FORM_SENTINEL) {
            ctls_extn_server_name_serialize(buffer,
                                            offset,
                                            &client_hello_extensions->server_name);
        }
        if (client_hello_extensions->maximum_fragment_length != 0) {
            ctls_extn_max_fragment_length_serialize(buffer,
                                                    offset,
                                                    &client_hello_extensions->
                                                    maximum_fragment_length);
        }
        if (client_hello_extensions->certificate_status_request.form !=
            CTLS_DATA_FORM_SENTINEL) {
            ctls_extn_certificate_status_request_serialize(buffer,
                                                           offset,
                                                           &client_hello_extensions->
                                                           certificate_status_request);
        }
        ctls_extn_supported_groups_serialize(buffer,
                                             offset,
                                             &client_hello_extensions->supported_groups);
        ctls_extn_signature_algorithm_serialize(buffer,
                                                offset,
                                                &client_hello_extensions->
                                                signature_algorithm);
        if (client_hello_extensions->heartbeat_mode !=
            CTLS_EXTN_HEARTBEAT_MODE_SENTINEL) {
            ctls_extn_heartbeat_mode_serialize(buffer,
                                               offset,
                                               &client_hello_extensions->heartbeat_mode);
        }
        if (client_hello_extensions->alpn.form != CTLS_DATA_FORM_SENTINEL) {
            ctls_extn_alpn_serialize(buffer, offset, &client_hello_extensions->alpn);
        }
        if (client_hello_extensions->signed_certificate_timestamp.form !=
            CTLS_DATA_FORM_SENTINEL) {
            ctls_extn_signed_certificate_timestamp_serialize(buffer,
                offset,
                &client_hello_extensions->signed_certificate_timestamp);
        }
        if (client_hello_extensions->client_certificate_type !=
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_extn_client_certificate_type_serialize(buffer,
                                                        offset,
                                                        &client_hello_extensions->
                                                        client_certificate_type);
        }
        if (client_hello_extensions->server_certificate_type !=
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            ctls_extn_server_certificate_type_serialize(buffer,
                                                        offset,
                                                        &client_hello_extensions->
                                                        server_certificate_type);
        }
        ctls_extn_supported_versions_serialize(buffer,
                                               offset,
                                               &client_hello_extensions->
                                               supported_versions);
        if (client_hello_extensions->certificate_authorities.form !=
            CTLS_DATA_FORM_SENTINEL) {
            ctls_extn_certificate_authorities_serialize(buffer,
                                                        offset,
                                                        &client_hello_extensions->
                                                        certificate_authorities);
        }
        if (client_hello_extensions->psk_key_exchange_modes !=
            CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_SENTINEL) {
            ctls_extn_psk_key_exchange_modes_serialize(buffer,
                                                       offset,
                                                       &client_hello_extensions->
                                                       psk_key_exchange_modes);
        }
        if (client_hello_extensions->signature_algorithm_cert !=
            CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL) {
            ctls_extn_signature_algorithm_cert_serialize(buffer,
                                                         offset,
                                                         &client_hello_extensions->
                                                         signature_algorithm_cert);
        }

        CTLS_CHECK_NULL(client_hello_extensions->key_share_entity);
        ctls_extn_key_share_serialize(buffer,
                                      offset,
                                      wire_format,
                                      client_hello_extensions->key_share_entity);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_extn_server_hello_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_extn_server_hello_t const *
                                             server_hello_extensions,
                                             ctls_wire_format_t wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(server_hello_extensions);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_status_t result = ctls_extn_supported_versions_serialize(buffer,
            offset,
            &server_hello_extensions->supported_versions);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return ctls_extn_key_share_serialize(buffer,
                                             offset,
                                             wire_format,
                                             server_hello_extensions->key_share_entity);
    }

    return CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_extn_server_hello_to_struct(
    ctls_extn_server_hello_t *server_hello_extensions,
    uint8_t *buffer,
    ctls_size_t *offset) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t result =
            ctls_extn_supported_versions_deserialize(&template->protocol_version,
                                                     &server_hello_extensions->
                                                     supported_versions);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_extn_key_share_deserialize(buffer,
                                           offset,
                                           CTLS_HELPER_ENTITY_OWNERSHIP_SERVER,
                                           &server_hello_extensions->key_share_entity);
}

ctls_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_extn_encrypted_extensions_to_struct(
    ctls_extn_encrypted_extensions_t *encrypted_extensions) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_STRUCT(encrypted_extensions);

    uint8_t is_initialized = 0;
    ctls_status_t result;

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_SERVER_NAME,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_server_name_deserialize(template->encrypted_extension.
                                                   predefined_extensions.server_name.data,
                                                   &template->encrypted_extension.
                                                   predefined_extensions.server_name.
                                                   length,
                                                   CTLS_DATA_FORM_OPAQUE,
                                                   &encrypted_extensions->server_name);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_max_fragment_length_deserialize(&template->encrypted_extension.
                                                           predefined_extensions.
                                                           maximum_fragment_length,
                                                           &encrypted_extensions->
                                                           maximum_fragment_length);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_SUPPORTED_GROUPS,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_supported_groups_deserialize(&template->dhe_group.dhe_group,
                                                        &encrypted_extensions->
                                                        supported_groups);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_HEARTBEAT,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_heartbeat_mode_deserialize(&template->encrypted_extension.
                                                      predefined_extensions.
                                                      heartbeat_mode,
                                                      &encrypted_extensions->
                                                      heartbeat_mode);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_alpn_deserialize(template->encrypted_extension.
                                            predefined_extensions.alpn.data,
                                            &template->encrypted_extension.
                                            predefined_extensions.alpn.length,
                                            CTLS_DATA_FORM_OPAQUE,
                                            &encrypted_extensions->alpn);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_client_certificate_type_deserialize(&template->
            encrypted_extension.predefined_extensions.client_certificate_type,
            &encrypted_extensions->client_certificate_type);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE,
                             CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_server_certificate_type_deserialize(&template->
            encrypted_extension.predefined_extensions.server_certificate_type,
            &encrypted_extensions->server_certificate_type);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    uint16_t size_of_expected_extensions =
            ctls_expected_extensions_size_get(&template->encrypted_extension.
                                              expected_extensions);

    if (size_of_expected_extensions != 0) return
            CTLS_STATUS_EXTN_UNEXPECTED_EXPECTED_EXTNS;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_extn_encrypted_extensions_t
                                                     const *encrypted_extensions,
                                                     ctls_wire_format_t wire_format) {
    ctls_status_t result;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        if (encrypted_extensions->server_name.form != CTLS_DATA_FORM_SENTINEL) {
            result = ctls_extn_server_name_serialize(buffer,
                                                     offset,
                                                     &encrypted_extensions->server_name);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        if (encrypted_extensions->maximum_fragment_length != 0) {
            result = ctls_extn_max_fragment_length_serialize(buffer,
                offset,
                &encrypted_extensions->maximum_fragment_length);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        result = ctls_extn_supported_groups_serialize(buffer,
                                                      offset,
                                                      &encrypted_extensions->
                                                      supported_groups);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if (encrypted_extensions->heartbeat_mode != CTLS_EXTN_HEARTBEAT_MODE_SENTINEL) {
            result = ctls_extn_heartbeat_mode_serialize(buffer,
                                                        offset,
                                                        &encrypted_extensions->
                                                        heartbeat_mode);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        if (encrypted_extensions->alpn.form != CTLS_DATA_FORM_SENTINEL) {
            result = ctls_extn_alpn_serialize(buffer,
                                              offset,
                                              &encrypted_extensions->alpn);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        if (encrypted_extensions->client_certificate_type !=
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            result = ctls_extn_client_certificate_type_serialize(buffer,
                offset,
                &encrypted_extensions->client_certificate_type);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        if (encrypted_extensions->server_certificate_type !=
            CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL) {
            result = ctls_extn_server_certificate_type_serialize(buffer,
                offset,
                &encrypted_extensions->server_certificate_type);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_extn_certificate_request_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_extn_certificate_request_to_struct(
    ctls_extn_certificate_request_t *certificate_request_extensions) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(certificate_request_extensions);
    CTLS_CHECK_NULL(template);

    uint8_t is_initialized = 0;
    ctls_status_t result;

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_STATUS_REQUEST,
                             CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_certificate_status_request_deserialize(template->
            certificate_request_extension.predefined_extensions.
            certificate_status_request.data,
            &template->certificate_request_extension.predefined_extensions.
            certificate_status_request.length,
            CTLS_DATA_FORM_OPAQUE,
            &certificate_request_extensions->certificate_status_request);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS,
                             CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_signature_algorithm_deserialize(&template->signature_algorithm.
                                                           signature_algorithm_type,
                                                           &certificate_request_extensions
                                                           ->signature_algorithm);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                             CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_signed_certificate_timestamp_deserialize(template->
            certificate_request_extension.predefined_extensions.
            signed_certificate_timestamp.data,
            &template->certificate_request_extension.predefined_extensions.
            signed_certificate_timestamp.length,
            CTLS_DATA_FORM_OPAQUE,
            &certificate_request_extensions->signed_certificate_timestamp);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES,
                             CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_certificate_authorities_deserialize(template->
            certificate_request_extension.predefined_extensions.
            certificate_authorities.data,
            &template->certificate_request_extension.predefined_extensions.
            certificate_authorities.length,
            CTLS_DATA_FORM_OPAQUE,
            &certificate_request_extensions->certificate_authorities);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT,
                             CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                             &is_initialized);
    if (is_initialized) {
        result = ctls_extn_signature_algorithm_cert_deserialize(&template->
            certificate_request_extension.predefined_extensions.
            signature_algorithm_cert,
            &certificate_request_extensions->signature_algorithm_cert);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_extn_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_extn_certificate_request_t const
                                                    *certificate_request,
                                                    ctls_wire_format_t wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_status_t result;

        if (certificate_request->certificate_status_request.form !=
            CTLS_DATA_FORM_SENTINEL) {
            result = ctls_extn_certificate_status_request_serialize(buffer,
                offset,
                &certificate_request->certificate_status_request);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        result = ctls_extn_signature_algorithm_serialize(buffer,
                                                         offset,
                                                         &certificate_request->
                                                         signature_algorithm);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if (certificate_request->signed_certificate_timestamp.form !=
            CTLS_DATA_FORM_SENTINEL) {
            result = ctls_extn_signed_certificate_timestamp_serialize(buffer,
                offset,
                &certificate_request->signed_certificate_timestamp);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        if (certificate_request->certificate_authorities.form == CTLS_DATA_FORM_OPAQUE) {
            result = ctls_extn_certificate_authorities_serialize(buffer,
                offset,
                &certificate_request->certificate_authorities);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_extn_certificate_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_extn_certificate_to_struct(
    ctls_extn_certificate_request_t *certificate_request_extensions) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

ctls_status_t ctls_extn_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_extn_certificate_request_t const *certificate_request,
                                            ctls_wire_format_t wire_format) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}