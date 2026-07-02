
//
// Created by Sanjay Kumar Kumaravelan on 18/04/26.
//

/*
 * Extension serialization for cTLS. See extensions.h for the design overview
 * (template compression, data forms, DEFAULT vs TRANSCRIPT_HASH wire formats)
 * and per-function API docs. Comments here describe the exact byte layouts.
 *
 * Two byte layouts appear throughout:
 *
 *   TLS 1.3 form (TRANSCRIPT_HASH — hashed, never sent), RFC 8446 §4.2:
 *       extension_type(u16) | extension_data_length(u16) | extension_data
 *
 *   cTLS form (DEFAULT — sent on wire): extension omitted entirely when the
 *   template predefines it; only dynamic data (key_share) is written, with
 *   no type and no length the template already implies.
 */

#include <string.h>
#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/templates.h"
#include "ctls/bytes.h"

/*
 * Generic loader for single-value enum extensions (supported_groups,
 * signature_algorithms, supported_versions, heartbeat, ...). The template
 * stores the bare value, so this is a 1- or 2-byte memcpy — no framing.
 */
ctls_status_t ctls_extn_enum_deserialize(void const *source,
                                         void *destination,
                                         ctls_helper_is_one_byte_t const isOneByte) {
    CTLS_CHECK_NULL(source);
    CTLS_CHECK_NULL(destination);

    if (isOneByte != CTLS_HELPER_IS_ONE_BYTE && isOneByte != CTLS_HELPER_IS_TWO_BYTE)
        return CTLS_STATUS_EXTN_DESER_ENUM_SIZE_FLAG;

    memcpy(destination, source, isOneByte == CTLS_HELPER_IS_ONE_BYTE ? 1 : 2);

    return CTLS_STATUS_SUCCESS;
}

/*
 * Generic writer for single-value enum extensions, TLS 1.3 form:
 *
 *     extension_type(u16) | extension_data_length(u16, =1|2) | value(u8|u16)
 *
 * Deviation from RFC 8446: the inner list wrappers (NamedGroupList,
 * SignatureSchemeList, ...) are dropped because the profile pins exactly one
 * value. Both peers reconstruct identically, so the transcript still matches.
 */
ctls_status_t ctls_extn_enum_serialize(uint8_t *buffer,
                                       ctls_size_t *offset,
                                       ctls_extn_type_t const extn_type,
                                       ctls_helper_is_one_byte_t const isOneByte,
                                       uint16_t const value) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    if (isOneByte != CTLS_HELPER_IS_ONE_BYTE && isOneByte != CTLS_HELPER_IS_TWO_BYTE)
        return CTLS_STATUS_EXTN_SER_ENUM_SIZE_FLAG;

    ctls_status_t result = ctls_write_u16(buffer, offset, extn_type, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u16(buffer, offset, isOneByte == CTLS_HELPER_IS_ONE_BYTE ? 1 : 2,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (isOneByte == CTLS_HELPER_IS_ONE_BYTE) {
        result = ctls_write_u8(buffer, offset, value, CTLS_SIZE_WIRE_BUFFER);
    } else {
        result = ctls_write_u16(buffer, offset, value, CTLS_SIZE_WIRE_BUFFER);
    }
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Does the template predefine extn_type for handshake message hsmg_type?
 * cTLS: a predefined extension exists on the connection but never on the
 * wire; an extension absent from the template simply does not exist. Each
 * extension has its own "present" signal: non-null blob, non-zero scalar, or
 * non-sentinel enum.
 */
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

/*
 * Blob passthrough writer:
 *
 *     [extension_type(u16) — skipped when CTLS_EXTN_TYPE_SENTINEL]
 *     | extension_data_length(u16) | raw bytes
 *
 * Template blobs store extension_data only (no type/length), matching
 * RFC 8446 §4.2 "opaque extension_data<0..2^16-1>" once framed here.
 * Callers that already wrote the type pass SENTINEL.
 */
ctls_status_t ctls_extn_opaque_serialize(uint8_t *destination_buffer,
                                         ctls_size_t *destination_offset,
                                         uint8_t const *source_buffer,
                                         ctls_size_t const source_length,
                                         ctls_extn_type_t const extension_type) {
    CTLS_CHECK_NULL_BUFFER(destination_buffer);
    CTLS_CHECK_NULL_OFFSET(destination_offset);
    CTLS_CHECK_NULL_BUFFER(source_buffer);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    if (extension_type != CTLS_EXTN_TYPE_SENTINEL) {
        result = ctls_write_u16(destination_buffer, destination_offset, extension_type,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }
    result = ctls_write_u16(destination_buffer, destination_offset, source_length,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_bytes(destination_buffer,
                     destination_offset,
                     source_length,
                     source_buffer,
                     CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;


    return CTLS_STATUS_SUCCESS;
}


/*
 * server_name, RFC 6066 §3. OPAQUE: alias the source blob, zero copy.
 * PARSED: decode the ServerNameList —
 *
 *     server_name_list_length(u16)
 *     then per entry: name_type(u8, host_name=0)
 *                   | host_name_length(u16) | host_name bytes
 */
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
        ctls_size_t const server_name_list_length = ctls_read_u16(buffer, &offset);
        ctls_size_t const server_name_list_absolute_length =
                offset + server_name_list_length;

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

/*
 * server_name, TLS 1.3 form (transcript). OPAQUE delegates to
 * ctls_extn_opaque_serialize (blob already holds the ServerNameList).
 * PARSED writes:
 *
 *     extension_type(u16) | list_length(u16, backfilled)
 *     then per entry: name_type(u8) | host_name_length(u16) | host_name
 *
 * Note: extension_data_length and server_name_list length collapse into the
 * single backfilled u16 — RFC 6066 carries both, here one u16 serves as both.
 */
ctls_status_t ctls_extn_server_name_serialize(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_extn_server_name_t const *
                                              server_name) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(server_name);

    if (server_name->form == CTLS_DATA_FORM_SENTINEL)
        return CTLS_STATUS_EXTN_INVALID_FORM;

    ctls_status_t result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SERVER_NAME,
                                          CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (server_name->form == CTLS_DATA_FORM_OPAQUE) {
        return ctls_extn_opaque_serialize(buffer,
                                          offset,
                                          server_name->opaque.buffer,
                                          server_name->opaque.buffer_length,
                                          CTLS_EXTN_TYPE_SENTINEL);
    }

    if (server_name->list_count <= 0) {
        result = ctls_write_u16(buffer, offset, 0, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        return CTLS_STATUS_SUCCESS;
    }
    ctls_size_t extensions_length_offset = *offset;
    *offset += 2;

    for (ctls_size_t i = 0; i < server_name->list_count; i++) {
        result = ctls_write_u8(buffer, offset, server_name->server_name_list[i].name_type,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u16(buffer,
                       offset,
                       server_name->server_name_list[i].server_name.buffer_length,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_bytes(buffer,
                         offset,
                         server_name->server_name_list[i].server_name.buffer_length,
                         server_name->server_name_list[i].server_name.buffer,
                         CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_write_u16(buffer,
                   &extensions_length_offset,
                   *offset - extensions_length_offset - 2,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;


    return CTLS_STATUS_SUCCESS;
}

/*
 * max_fragment_length, RFC 6066 §4:
 * "enum{ 2^9(1), 2^10(2), 2^11(3), 2^12(4), (255) } MaxFragmentLength;"
 * One byte — handled by the generic enum helpers.
 */
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

/*
 * Sender side: if the peer asked for certificate status during the
 * handshake, attach the canned OCSP response DER for this entity (form =
 * OPAQUE); otherwise mark the extension absent (form = SENTINEL).
 */
ctls_status_t ctls_extn_certificate_status_request_create(
    ctls_extn_certificate_status_request_t *certificate_status_request,
    ctls_entity_t const entity) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(certificate_status_request);
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_EXTN_CERT_STATUS_INVALID_ENTITY;

    if (!hshk_data->isCertificateStatusRequested) {
        certificate_status_request->form = CTLS_DATA_FORM_SENTINEL;
        return CTLS_STATUS_SUCCESS;
    }

    certificate_status_request->form = CTLS_DATA_FORM_OPAQUE;
    certificate_status_request->opaque.buffer = (uint8_t *) (entity == CTLS_ENTITY_CLIENT
        ? client_ocsp_response_der
        : server_ocsp_response_der);
    certificate_status_request->opaque.buffer_length = entity == CTLS_ENTITY_CLIENT
                                                           ? client_ocsp_response_der_length
                                                           : server_ocsp_response_der_length;

    return CTLS_STATUS_SUCCESS;
}

/*
 * status_request, RFC 6066 §8. OPAQUE: alias blob. PARSED layout read:
 *
 *     status_type(u8, must be ocsp=1)
 *     | responder_id_list_length(u16, skipped)
 *     | responder_id_length(u16, skipped)
 *     | responder_id(u8 stub)
 *     | request_extensions_length(u16, skipped)
 *     | request_extensions(u8 stub)
 *
 * RFC 6066 allows variable-length ResponderID and Extensions lists; the
 * profile fixes both to 1-byte stubs (value 0), so the list lengths are
 * skipped rather than honored.
 */
ctls_status_t ctls_extn_certificate_status_request_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t const form,
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
            CTLS_EXTN_CERTIFICATE_STATUS_TYPE_OSCP)
            return CTLS_STATUS_EXTN_INVALID_STATUS_TYPE;

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

/*
 * status_request, TLS 1.3 form (transcript). OPAQUE delegates to opaque
 * writer. PARSED writes:
 *
 *     extension_type(u16) | status_type(u8)
 *     | responder_id_list_length(u16, backfilled)
 *     | responder_id_length(u16) | responder_id(u8)
 *     | request_extensions(u8)
 */
ctls_status_t ctls_extn_certificate_status_request_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_status_request_t const *certificate_status_request) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_status_request);

    if (certificate_status_request->form == CTLS_DATA_FORM_SENTINEL)
        return CTLS_STATUS_EXTN_INVALID_FORM;

    ctls_status_t result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_STATUS_REQUEST,
                                          CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (certificate_status_request->form == CTLS_DATA_FORM_OPAQUE) {
        return ctls_extn_opaque_serialize(buffer,
                                          offset,
                                          certificate_status_request->opaque.buffer,
                                          certificate_status_request->opaque.
                                          buffer_length,
                                          CTLS_EXTN_TYPE_SENTINEL);
    }

    result = ctls_write_u8(buffer,
                  offset,
                  certificate_status_request->status_request.certificate_status_type,
                  CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t responder_list_length_offset = *offset;
    *offset += 2;

    result = ctls_write_u16(buffer,
                   offset,
                   sizeof(certificate_status_request->status_request.ocsp_status_request.
                       responder_id),
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u8(buffer,
                  offset,
                  certificate_status_request->status_request.ocsp_status_request.
                  responder_id,
                  CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u8(buffer,
                  offset,
                  certificate_status_request->status_request.ocsp_status_request.
                  request_extensions,
                  CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_u16(buffer,
                   &responder_list_length_offset,
                   *offset - responder_list_length_offset,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;


    return CTLS_STATUS_SUCCESS;
}

/*
 * supported_groups, RFC 8446 §4.2.7 ("NamedGroup named_group_list
 * <2..2^16-1>;") — collapsed to the single u16 NamedGroup the template pins.
 */
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

/*
 * signature_algorithms, RFC 8446 §4.2.3 ("SignatureScheme
 * supported_signature_algorithms<2..2^16-2>;") — collapsed to the single
 * u16 SignatureScheme the template pins.
 */
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

/*
 * signature_algorithms_cert, RFC 8446 §4.2.3 — same encoding as
 * signature_algorithms, scoped to signatures inside certificates.
 */
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

/*
 * heartbeat, RFC 6520 §2 — single HeartbeatMode byte:
 * peer_allowed_to_send(1) | peer_not_allowed_to_send(2).
 */
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

/*
 * ALPN, RFC 7301 §3.1. OPAQUE: alias blob. PARSED: decode the
 * ProtocolNameList —
 *
 *     protocol_name_list_length(u16)
 *     then per entry: protocol_name_length(u8) | protocol_name bytes
 */
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

/*
 * ALPN, TLS 1.3 form (transcript). Same single-length collapse as
 * server_name: extension_type(u16) | list_length(u16, backfilled) | entries.
 */
ctls_status_t ctls_extn_alpn_serialize(uint8_t *buffer,
                                       ctls_size_t *offset,
                                       ctls_extn_alpn_t const *alpn) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(alpn);

    if (alpn->form == CTLS_DATA_FORM_SENTINEL) return CTLS_STATUS_EXTN_ALPN_INVALID_FORM;

    ctls_status_t result = ctls_write_u16(buffer, offset,
                                          CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                          CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (alpn->form == CTLS_DATA_FORM_OPAQUE) {
        return ctls_extn_opaque_serialize(buffer,
                                          offset,
                                          alpn->opaque.buffer,
                                          alpn->opaque.buffer_length,
                                          CTLS_EXTN_TYPE_SENTINEL);
    }

    if (alpn->list_count <= 0) {
        result = ctls_write_u16(buffer, offset, 0, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        return CTLS_STATUS_SUCCESS;
    }

    ctls_size_t extensions_length_offset = *offset;
    *offset += 2;

    for (uint8_t i = 0; i < alpn->list_count; i++) {
        result = ctls_write_u8(buffer, offset, alpn->alpn_list[i].protocol_name_length,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_bytes(buffer,
                         offset,
                         alpn->alpn_list[i].protocol_name_length,
                         alpn->alpn_list[i].protocol_name,
                         CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_write_u16(buffer,
                   &extensions_length_offset,
                   *offset - extensions_length_offset - 2,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;


    return CTLS_STATUS_SUCCESS;
}

/*
 * Sender side: attach canned SCT DER for this entity (form = OPAQUE), or
 * mark absent. RFC 6962 §3.3 — SCT delivered via TLS extension.
 */
ctls_status_t ctls_extn_signed_certificate_timestamp_create(
    ctls_extn_signed_certificate_timestamp_t *signed_certificate_timestamp,
    ctls_entity_t const entity) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hshk_data);
    CTLS_CHECK_NULL_STRUCT(signed_certificate_timestamp);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_EXTN_INVALID_ENTITY;

    if (hshk_data->isSignedCertificateTimestampRequested) {
        signed_certificate_timestamp->form = CTLS_DATA_FORM_SENTINEL;
        return CTLS_STATUS_SUCCESS;
    }

    signed_certificate_timestamp->form = CTLS_DATA_FORM_OPAQUE;
    signed_certificate_timestamp->opaque.buffer = (uint8_t *) (
        entity == CTLS_ENTITY_CLIENT ? client_sct_der : server_sct_der);
    signed_certificate_timestamp->opaque.buffer_length = entity == CTLS_ENTITY_CLIENT
                                                             ? client_sct_der_length
                                                             : server_sct_der_length;

    return CTLS_STATUS_SUCCESS;
}

/*
 * SCT, RFC 6962 §3.2. OPAQUE: alias blob. PARSED layout read (profile
 * variant of SignedCertificateTimestamp, single SCT, no list wrapper):
 *
 *     sct_version(u8) | log_id(32B) | timestamp(u64)
 *     | extensions(u8 stub) | signature_algorithm(u16)
 *     | certificate_length(u16) | certificate bytes
 */
ctls_status_t ctls_extn_signed_certificate_timestamp_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t const form,
    ctls_extn_signed_certificate_timestamp_t *signed_certificate_timestamp) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(buffer_length);
    CTLS_CHECK_NULL_STRUCT(signed_certificate_timestamp);

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

/*
 * SCT, TLS 1.3 form (transcript). OPAQUE delegates to opaque writer.
 * PARSED writes:
 *
 *     extension_type(u16) | extension_data_length(u16, backfilled)
 *     | sct_version(u8) | log_id(32B) | timestamp(u64)
 *     | extensions(u8) | signature_algorithm(u16)
 *     | certificate_length(u16) | certificate bytes
 */
ctls_status_t ctls_extn_signed_certificate_timestamp_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signed_certificate_timestamp_t const *signed_certificate_timestamp) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(signed_certificate_timestamp);

    if (signed_certificate_timestamp->form == CTLS_DATA_FORM_SENTINEL)
        return CTLS_STATUS_EXTN_INVALID_FORM;

    ctls_status_t result = ctls_write_u16(buffer, offset,
                                          CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                                          CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (signed_certificate_timestamp->form == CTLS_DATA_FORM_OPAQUE) {
        return ctls_extn_opaque_serialize(buffer,
                                          offset,
                                          signed_certificate_timestamp->opaque.buffer,
                                          signed_certificate_timestamp->opaque.
                                          buffer_length,
                                          CTLS_EXTN_TYPE_SENTINEL);
    }

    /* NOTE: pre-existing duplicate write of the same u16 here (also written
     * above) — not touched, out of scope for the bounds-check pass. */
    result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t length_offset = *offset;
    *offset += 2;

    result = ctls_write_u8(buffer,
                  offset,
                  signed_certificate_timestamp->signed_certificate_timestamp.sct_version,
                  CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_bytes(buffer,
                     offset,
                     CTLS_SIZE_SCT_LOG_ID,
                     signed_certificate_timestamp->signed_certificate_timestamp.log_id,
                     CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u64(buffer,
                   offset,
                   signed_certificate_timestamp->signed_certificate_timestamp.timestamp,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u8(buffer,
                  offset,
                  signed_certificate_timestamp->signed_certificate_timestamp.extensions,
                  CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u16(buffer,
                   offset,
                   signed_certificate_timestamp->signed_certificate_timestamp.
                   signature_algorithm,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_bytes(buffer,
                     offset,
                     signed_certificate_timestamp->signed_certificate_timestamp.
                     certificate.buffer_length,
                     signed_certificate_timestamp->signed_certificate_timestamp.
                     certificate.buffer,
                     CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_u16(buffer, &length_offset, *offset - length_offset - 2,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}

/*
 * client_certificate_type, RFC 7250 — single CertificateType byte the
 * template pins (X509(0) | RawPublicKey(2)). List wrapper dropped.
 */
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

/* server_certificate_type, RFC 7250 — same encoding as client variant. */
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

/*
 * supported_versions, RFC 8446 §4.2.1. TLS 1.3 sends a version list in CH
 * and one selected_version in SH; the template pins ProtocolVersion 0x0304,
 * so both collapse to a single u16.
 */
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

/*
 * psk_key_exchange_modes, RFC 8446 §4.2.9 ("PskKeyExchangeMode
 * ke_modes<1..255>;") — collapsed to the single u8 mode the template pins.
 */
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

/*
 * certificate_authorities, RFC 8446 §4.2.4 ("DistinguishedName
 * authorities<3..2^16-1>;"). OPAQUE: alias blob. PARSED: single DN —
 *
 *     distinguished_name_length(u16) | DER-encoded DN bytes
 */
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
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_authorities);

    if (certificate_authorities->form == CTLS_DATA_FORM_SENTINEL) return
            CTLS_STATUS_EXTN_CERT_AUTH_INVALID_FORM;

    ctls_status_t result = ctls_write_u16(buffer, offset,
                                          CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES,
                                          CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (certificate_authorities->form == CTLS_DATA_FORM_OPAQUE) {
        return ctls_extn_opaque_serialize(buffer,
                                          offset,
                                          certificate_authorities->opaque.buffer,
                                          certificate_authorities->opaque.buffer_length,
                                          CTLS_EXTN_TYPE_SENTINEL);
    }

    result = ctls_write_u16(buffer, offset, certificate_authorities->distinguished_name_length,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_bytes(buffer,
                     offset,
                     certificate_authorities->distinguished_name_length,
                     certificate_authorities->distinguished_name,
                     CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;


    return CTLS_STATUS_SUCCESS;
}

/*
 * post_handshake_auth, RFC 8446 §4.2.6: "The 'extension_data' field of the
 * 'post_handshake_auth' extension is zero length." Deserialize copies the
 * template flag byte.
 */
ctls_status_t ctls_extn_post_handshake_auth_deserialize(
    ctls_extn_post_handshake_auth_t const *source,
    ctls_extn_post_handshake_auth_t *post_handshake_auth) {
    return ctls_extn_enum_deserialize(source,
                                      post_handshake_auth,
                                      CTLS_HELPER_IS_ONE_BYTE);
}

/*
 * post_handshake_auth, TLS 1.3 form: extension_type(u16) | length(u16)=0.
 * Writes nothing when the flag is unset (extension absent).
 */
ctls_status_t ctls_extn_post_handshake_auth_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_post_handshake_auth_t const *post_handshake_auth) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(post_handshake_auth);

    if (!*post_handshake_auth) return CTLS_STATUS_SUCCESS;

    ctls_status_t result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH,
                                          CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u16(buffer, offset, 0, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}

/*
 * key_share, RFC 8446 §4.2.8. TLS 1.3 KeyShareEntry is
 * { NamedGroup group(u16); opaque key_exchange<1..2^16-1>; } — in cTLS the
 * group and key length come from the template, so the wire carries only the
 * raw CTLS_SIZE_KEY_SHARE key bytes. They are copied into hshk_data's
 * client/server ephemeral key slot per entity_ownership, and *key_share is
 * pointed at that storage.
 */
ctls_status_t ctls_extn_key_share_deserialize(uint8_t const *buffer,
                                              ctls_size_t *offset,
                                              ctls_entity_t const entity,
                                              ctls_extn_key_share_t *key_share) {
    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(key_share);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_EXTN_INVALID_ENTITY;

    uint8_t public_ephemeral_key[CTLS_SIZE_KEY_SHARE];

    ctls_read_bytes(public_ephemeral_key, CTLS_SIZE_KEY_SHARE, buffer, offset);
    ctls_status_t result = ctls_ephemeral_public_key_import(public_ephemeral_key,
                                                                CTLS_SIZE_KEY_SHARE,
                                                                &crypto->
                                                                peer_public_ephemeral_key);
    if (result != CTLS_STATUS_SUCCESS) return result;

    *key_share = &crypto->peer_public_ephemeral_key;
    return CTLS_STATUS_SUCCESS;
}

/*
 * key_share writer.
 *
 *     DEFAULT (cTLS wire):  key_exchange_length(u16) | key bytes
 *     TRANSCRIPT_HASH:      extension_type(u16) | key_exchange_length(u16)
 *                           | key bytes
 */
ctls_status_t ctls_extn_key_share_serialize(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_wire_format_t const wire_format,
                                            ctls_extn_key_share_t key_share) {
    ctls_crypto_t const *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(crypto);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_write_u16(buffer, offset, CTLS_SIZE_KEY_SHARE, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    uint8_t raw_bytes[CTLS_SIZE_KEY_SHARE];
    ctls_size_t bytes_written;
    result = ctls_ephemeral_public_key_export(key_share,
        raw_bytes,
        CTLS_SIZE_KEY_SHARE,
        &bytes_written);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_bytes(buffer, offset, bytes_written, raw_bytes, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}


/* Element count of a template expected_extensions array. */
uint8_t ctls_expected_extensions_size_get(void) {
    return sizeof(ctls_tmpl_expected_extensions_t) / sizeof(ctls_extn_type_t);
}

/*
 * Build the full ClientHello extension set. For each extension: ask
 * ctls_extn_is_initialized whether the template predefines it, and if so
 * load it from the template (OPAQUE blobs alias template memory, scalars
 * are copied). Then, if the template expects key_share dynamically,
 * generate the client ephemeral key pair and reference its public half —
 * the only extension data that will hit the cTLS wire.
 */
ctls_status_t ctls_extn_client_hello_create(
    ctls_extn_client_hello_t *client_hello_extensions) {
    ctls_template_t const *template = ctls_template_get();

    ctls_crypto_t *crypto = ctls_crypto_get();

    CTLS_CHECK_NULL_STRUCT(client_hello_extensions);
    CTLS_CHECK_NULL_STRUCT(template);
    CTLS_CHECK_NULL_STRUCT(crypto);

    uint8_t const size_of_expected_extensions = ctls_expected_extensions_size_get();
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

        result = ctls_ephemeral_key_pair_generate(&crypto->self_ephemeral_key_pair);
        if (result != CTLS_STATUS_SUCCESS) return result;

        client_hello_extensions->key_share_entity = &crypto->self_ephemeral_key_pair;
    }

    return CTLS_STATUS_SUCCESS;
}


/*
 * Parse ClientHello extensions from compact cTLS wire bytes.
 *
 * DEFAULT wire carries only the key_share:
 *     key_exchange_length(u16, skip — fixed CTLS_SIZE_KEY_SHARE)
 *     | raw key bytes (CTLS_SIZE_KEY_SHARE bytes)
 *
 * All other extensions are template-pinned and never transmitted.
 */
ctls_status_t ctls_extn_client_hello_to_struct(ctls_extn_client_hello_t *extensions,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(extensions);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    /* Load template-pinned extension fields so TRANSCRIPT_HASH reconstruction
     * matches what the client serialized. The generated ephemeral key pair is
     * overwritten by ctls_recd_server_hello_create later. */
    ctls_status_t result = ctls_extn_client_hello_create(extensions);
    if (result != CTLS_STATUS_SUCCESS) return result;

    *offset += 2; /* skip key_exchange_length u16 — always CTLS_SIZE_KEY_SHARE */
    return ctls_extn_key_share_deserialize(buffer,
                                           offset,
                                           CTLS_ENTITY_CLIENT,
                                           &extensions->key_share_entity);
}

/*
 * Emit ClientHello extensions.
 *
 * DEFAULT (cTLS wire): predefined extensions are compressed away entirely;
 * only the key_share key bytes are written. The u16 length prefix is added
 * only when the template does not pin key_share_length.
 *
 * TRANSCRIPT_HASH: reconstruct every present extension in TLS 1.3 Extension
 * framing (type | length | data), in struct order, key_share last. This
 * byte stream feeds the transcript hash so the key schedule matches what a
 * TLS 1.3 peer would compute.
 */
ctls_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_extn_client_hello_t const *
                                             client_hello_extensions,
                                             ctls_wire_format_t const wire_format) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(client_hello_extensions);
    CTLS_CHECK_NULL(template);


    uint8_t const size_of_expected_extensions = ctls_expected_extensions_size_get();

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
            if (template->client_hello_extension.expected_extensions[i] ==
                CTLS_EXTN_TYPE_KEY_SHARE) {
                ctls_status_t const result = ctls_extn_key_share_serialize(buffer,
                    offset,
                    wire_format,
                    client_hello_extensions->key_share_entity);
                if (result != CTLS_STATUS_SUCCESS) return result;
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

    return CTLS_STATUS_EXTN_CH_INVALID_WIRE_FORMAT;
}

/*
 * Build ServerHello extensions (server-side create):
 *   - Generate the server's own ephemeral key pair (X25519).
 *   - Set key_share_entity to point at the newly generated key handle.
 *   - Load supported_versions from the template (never sent on wire;
 *     reconstructed by the client from its own template copy).
 */
ctls_status_t ctls_extn_server_hello_create(
    ctls_extn_server_hello_t *server_hello_extensions) {
    ctls_crypto_t *crypto = ctls_crypto_get();
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(server_hello_extensions);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(template);

    ctls_status_t result =
            ctls_ephemeral_key_pair_generate(&crypto->self_ephemeral_key_pair);
    if (result != CTLS_STATUS_SUCCESS) return result;

    server_hello_extensions->key_share_entity = &crypto->self_ephemeral_key_pair;

    return ctls_extn_supported_versions_deserialize(&template->protocol_version,
                                                    &server_hello_extensions->
                                                    supported_versions);
}

/*
 * Emit ServerHello extensions. RFC 8446 §4.1.3 requires supported_versions
 * and key_share in SH. TRANSCRIPT_HASH reconstructs both in TLS 1.3
 * framing; DEFAULT is empty (client-only build never sends SH).
 */
ctls_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_extn_server_hello_t const *
                                             server_hello_extensions,
                                             ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(server_hello_extensions);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        /* Only the raw key bytes cross the wire; no length prefix, matching
         * ctls_extn_server_hello_to_struct which reads CTLS_SIZE_KEY_SHARE bytes
         * directly via ctls_extn_key_share_deserialize. */
        uint8_t raw_bytes[CTLS_SIZE_KEY_SHARE];
        ctls_size_t bytes_written = 0;
        ctls_status_t result =
                ctls_ephemeral_public_key_export(server_hello_extensions->
                                                 key_share_entity,
                                                 raw_bytes,
                                                 CTLS_SIZE_KEY_SHARE,
                                                 &bytes_written);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_bytes(buffer, offset, bytes_written, raw_bytes,
                                  CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        return CTLS_STATUS_SUCCESS;
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

    return CTLS_STATUS_EXTN_SH_INVALID_WIRE_FORMAT;
}

/*
 * Rebuild ServerHello extensions on receive. supported_versions comes from
 * the template (predefined, never on wire); key_share is the only wire
 * field — raw server public key bytes at *offset.
 */
ctls_status_t ctls_extn_server_hello_to_struct(
    ctls_extn_server_hello_t *server_hello_extensions,
    uint8_t const *buffer,
    ctls_size_t *offset) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(server_hello_extensions);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(template);

    ctls_status_t result =
            ctls_extn_supported_versions_deserialize(&template->protocol_version,
                                                     &server_hello_extensions->
                                                     supported_versions);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_extn_key_share_deserialize(buffer,
                                           offset,
                                           CTLS_ENTITY_SERVER,
                                           &server_hello_extensions->key_share_entity);
}

ctls_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Rebuild EncryptedExtensions content (RFC 8446 §4.3.1) purely from the
 * template — in cTLS none of these travel on the wire. Errors if the
 * template expects dynamic extensions for EE (none are defined).
 */
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

    uint8_t const n = ctls_expected_extensions_size_get();
    for (uint8_t i = 0; i < n; i++) {
        if (template->encrypted_extension.expected_extensions[i] != 0) return
                CTLS_STATUS_EXTN_UNEXPECTED_EXPECTED_EXTNS;
    }

    return CTLS_STATUS_SUCCESS;
}

/*
 * Emit EncryptedExtensions extensions. TRANSCRIPT_HASH reconstructs each
 * present extension in TLS 1.3 framing, struct order. DEFAULT is empty —
 * everything here is template-predefined, nothing goes on the wire.
 */
ctls_status_t ctls_extn_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_extn_encrypted_extensions_t
                                                     const *encrypted_extensions,
                                                     ctls_wire_format_t const
                                                     wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(encrypted_extensions);

    ctls_status_t result;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        return CTLS_STATUS_SUCCESS;
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

    return CTLS_STATUS_EXTN_EE_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_extn_certificate_request_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Rebuild CertificateRequest extensions (RFC 8446 §4.3.2) from the
 * template. signature_algorithms is the one RFC-mandatory extension there;
 * the rest load only if predefined.
 */
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

/*
 * Emit CertificateRequest extensions (TRANSCRIPT_HASH reconstruction,
 * TLS 1.3 framing, struct order). DEFAULT is empty — template-predefined.
 */
ctls_status_t ctls_extn_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_extn_certificate_request_t const
                                                    *certificate_request,
                                                    ctls_wire_format_t const
                                                    wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_request);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        return CTLS_STATUS_SUCCESS;
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

    return CTLS_STATUS_EXTN_CR_INVALID_WIRE_FORMAT;
}

/*
 * Build per-CertificateEntry extensions from handshake state. RFC 8446
 * §4.4.2: "Valid extensions for server certificates at present include the
 * OCSP Status extension [RFC6066] and the SignedCertificateTimestamp
 * extension [RFC6962]" — attached only when the peer requested them.
 */
ctls_status_t ctls_extn_certificate_create(ctls_extn_certificate_t *ctls_certificate,
                                           ctls_entity_t const entity) {
    ctls_hshk_data_t const *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(ctls_certificate);
    CTLS_CHECK_NULL_STRUCT(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER) return
            CTLS_STATUS_EXTN_CERT_CREATE_INVALID_ENTITY;

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    if (hshk_data->isCertificateStatusRequested) {
        result = ctls_extn_certificate_status_request_create(&ctls_certificate->
            certificate_status_request,
            entity);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }
    if (hshk_data->isSignedCertificateTimestampRequested) {
        result = ctls_extn_signed_certificate_timestamp_create(&ctls_certificate->
            signed_certificate_timestamp,
            entity);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    return result;
}

/* Rebuild per-CertificateEntry extensions from the template. */
ctls_status_t ctls_extn_certificate_to_struct(
    ctls_extn_certificate_t *certificate_extensions) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(certificate_extensions);
    CTLS_CHECK_NULL(template);

    uint8_t is_initialized = 0;
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_STATUS_REQUEST,
                                      CTLS_HSMG_TYPE_CERTIFICATE,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_certificate_status_request_deserialize(template->
            certificate_request_extension.predefined_extensions.
            certificate_status_request.data,
            &template->certificate_request_extension.predefined_extensions.
            certificate_status_request.length,
            CTLS_DATA_FORM_OPAQUE,
            &certificate_extensions->certificate_status_request);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }


    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                                      CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (is_initialized) {
        result = ctls_extn_signed_certificate_timestamp_deserialize(template->
            certificate_request_extension.predefined_extensions.
            signed_certificate_timestamp.data,
            &template->certificate_request_extension.predefined_extensions.
            signed_certificate_timestamp.length,
            CTLS_DATA_FORM_OPAQUE,
            &certificate_extensions->signed_certificate_timestamp);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }


    return result;
}

/*
 * Emit per-CertificateEntry extensions (TRANSCRIPT_HASH reconstruction,
 * TLS 1.3 framing). DEFAULT is empty.
 */
ctls_status_t ctls_extn_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_extn_certificate_t const *
                                            certificate_extensions,
                                            ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_extensions);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        return CTLS_STATUS_SUCCESS;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_status_t result;

        if (certificate_extensions->certificate_status_request.form !=
            CTLS_DATA_FORM_SENTINEL) {
            result = ctls_extn_certificate_status_request_serialize(buffer,
                offset,
                &certificate_extensions->certificate_status_request);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        if (certificate_extensions->signed_certificate_timestamp.form !=
            CTLS_DATA_FORM_SENTINEL) {
            result = ctls_extn_signed_certificate_timestamp_serialize(buffer,
                offset,
                &certificate_extensions->signed_certificate_timestamp);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_EXTN_CERT_INVALID_WIRE_FORMAT;
}
