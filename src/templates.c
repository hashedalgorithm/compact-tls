//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#include "ctls/templates.h"

#include "ctls/bytes.h"
#include "ctls/ctls.h"

/*
 * Template handling. See templates.h for what a template is and config.h
 * for the built-in template's values. Comments here describe the exact byte
 * layouts of the template's canonical wire form.
 */

const ctls_template_t ctls_template_1 = CTLS_TEMPLATE_1_INIT;


/*
 * Resolve profile_id -> built-in template. cTLS peers agree on the profile
 * out of band; an unknown id cannot be negotiated away, so it is a hard
 * failure (CTLS_STATUS_TMPL_UNKNOWN_PROFILE).
 */
ctls_status_t ctls_template_set(uint8_t const profile_id, ctls_context_t *context) {
    switch (profile_id) {
        case 0x01: {
            context->template = &ctls_template_1;
            return CTLS_STATUS_SUCCESS;
        }
        default: {
            context->template = NULL;
            return CTLS_STATUS_TMPL_UNKNOWN_PROFILE;
        }
    }
}

/*
 * Serialize one per-message extension block of the template:
 *
 *     predefined_extensions_length(u16, backfilled)
 *     | per initialized predefined extension:
 *           extension_type(u16) | data_length(u16) | raw template data
 *     | expected_extensions_length(u16, backfilled)
 *     | expected extension type codes (u16 each)
 *     | self_delimiting_extensions_length(u16, backfilled)
 *     | self-delimiting extension type codes (u16 each)
 *     | allow_additional(u8)
 *
 * Predefined extensions are written in TLS 1.3 Extension framing
 * (RFC 8446 §4.2) via ctls_extn_opaque_serialize — scalar values are passed
 * as raw bytes of their in-memory width. key_share may not appear in either
 * type-code list: it is handled by the dhe_group template element.
 */
ctls_status_t ctls_tmpl_extension_to_wire(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          ctls_hsmg_type_t type,
                                          ctls_tmpl_extension_t const *extensions) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(extensions);

    uint8_t is_initialized = 0;
    ctls_size_t predefined_extensions_length_offset = *offset;
    (*offset) += 2;

    ctls_status_t result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SERVER_NAME,
                                                    type,
                                                    &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            extensions->predefined_extensions.server_name.
                                            data,
                                            extensions->predefined_extensions.server_name.
                                            length,
                                            CTLS_EXTN_TYPE_SERVER_NAME);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .maximum_fragment_length,
                                            sizeof(extensions->predefined_extensions.
                                                maximum_fragment_length),
                                            CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_STATUS_REQUEST,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            extensions->predefined_extensions.
                                            certificate_status_request.data,
                                            extensions->predefined_extensions.
                                            certificate_status_request.length,
                                            CTLS_EXTN_TYPE_STATUS_REQUEST);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_HEARTBEAT, type, &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .heartbeat_mode,
                                            sizeof(extensions->predefined_extensions.
                                                heartbeat_mode),
                                            CTLS_EXTN_TYPE_HEARTBEAT);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result =
            ctls_extn_is_initialized(CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                     type,
                                     &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            extensions->predefined_extensions.alpn.data,
                                            extensions->predefined_extensions.alpn.length,
                                            CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            extensions->predefined_extensions.
                                            signed_certificate_timestamp.data,
                                            extensions->predefined_extensions.
                                            signed_certificate_timestamp.length,
                                            CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .client_certificate_type,
                                            sizeof(extensions->predefined_extensions.
                                                client_certificate_type),
                                            CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .server_certificate_type,
                                            sizeof(extensions->predefined_extensions.
                                                server_certificate_type),
                                            CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .psk_key_exchange_modes,
                                            sizeof(extensions->predefined_extensions.
                                                psk_key_exchange_modes),
                                            CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            extensions->predefined_extensions.
                                            certificate_authorities.data,
                                            extensions->predefined_extensions.
                                            certificate_authorities.length,
                                            CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .post_handshake_auth,
                                            sizeof(extensions->predefined_extensions.
                                                post_handshake_auth),
                                            CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_extn_is_initialized(CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT,
                                      type,
                                      &is_initialized);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (is_initialized) {
        result = ctls_extn_opaque_serialize(buffer,
                                            offset,
                                            (uint8_t *) &extensions->predefined_extensions
                                            .signature_algorithm_cert,
                                            sizeof(extensions->predefined_extensions.
                                                signature_algorithm_cert),
                                            CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    result = ctls_write_u16(buffer,
                   &predefined_extensions_length_offset,
                   *offset - predefined_extensions_length_offset,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t expected_extensions_length = *offset;
    *offset += 2;
    for (size_t i = 0; i < sizeof(extensions->expected_extensions) / sizeof(extensions->
                           expected_extensions[0]); i++) {
        if (extensions->expected_extensions[i] == CTLS_EXTN_TYPE_KEY_SHARE)
            return CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_EXPECTED;

        result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }
    result = ctls_write_u16(buffer,
                   &expected_extensions_length,
                   *offset - expected_extensions_length,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t self_delimited_extensions_length = *offset;
    *offset += 2;
    for (size_t i = 0; i < sizeof(extensions->self_delimiting_aextensions) / sizeof(
                           extensions->self_delimiting_aextensions[0]); i++) {
        if (extensions->self_delimiting_aextensions[i] == CTLS_EXTN_TYPE_KEY_SHARE)
            return CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_SELF_DELIM;

        result = ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }
    result = ctls_write_u16(buffer,
                   &self_delimited_extensions_length,
                   *offset - self_delimited_extensions_length,
                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_u8(buffer, offset, extensions->allow_additional, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}


/*
 * Serialize one template element as TLV:
 *
 *     element_type(u16) | element_length(u32) | value
 *
 * Value layouts:
 *     PROFILE_ID          id_length(u8) | profile_id(u8)
 *     VERSION             protocol_version(u16)
 *     CIPHER_SUITE        cipher_suite(u16)
 *     DH_GROUP            dhe_group(u16) | key_share_length(u16)
 *     SIGNATURE_ALGORITHM scheme(u16) | signature_length(u16)
 *     RANDOM              random_length(u16)
 *     MUTUAL_AUTH         mutual_auth(u16)
 *     HANDSHAKE_FRAMING   handshake_framing(u16)
 *     *_EXTENSIONS        extension block, see ctls_tmpl_extension_to_wire
 *     KNOWN_CERTIFICATES  per entry: certificate_id(u8) | DER bytes
 *     FINISHED_SIZE       finished_size(u16)
 */
ctls_status_t ctls_template_element_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_template_t const *tmpl,
                                            ctls_tmpl_type_t const type) {
    ctls_status_t result = CTLS_STATUS_SUCCESS;
    switch (type) {
        case CTLS_TMPL_TYPE_PROFILE_ID:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_PROFILE_ID, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(uint8_t) + sizeof(tmpl->profile_id),
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u8(buffer, offset, sizeof(tmpl->profile_id), CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u8(buffer, offset, tmpl->profile_id, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_VERSION:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_VERSION, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(tmpl->protocol_version),
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->protocol_version, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_CIPHER_SUITE:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CIPHER_SUITE, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(tmpl->cipher_suite),
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->cipher_suite, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_DH_GROUP:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_DH_GROUP, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer,
                           offset,
                           sizeof(tmpl->dhe_group.dhe_group) + sizeof(tmpl->dhe_group.
                               key_share_length),
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->dhe_group.dhe_group, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->dhe_group.key_share_length,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer,
                           offset,
                           sizeof(tmpl->signature_algorithm.signature_algorithm_type) +
                           sizeof(tmpl->signature_algorithm.signature_length),
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer,
                           offset,
                           tmpl->signature_algorithm.signature_algorithm_type,
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->signature_algorithm.signature_length,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_RANDOM:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_RANDOM, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(tmpl->random), CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->random, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_MUTUAL_AUTH:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_MUTUAL_AUTH, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(tmpl->mutual_auth), CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->mutual_auth, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_HANDSHAKE_FRAMING:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_HANDSHAKE_FRAMING,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(tmpl->handshake_framing),
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->handshake_framing, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        case CTLS_TMPL_TYPE_CLIENT_HELLO_EXTENSIONS:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CLIENT_HELLO_EXTENSIONS,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_CLIENT_HELLO,
                                        &tmpl->client_hello_extension);
            break;
        case CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_SERVER_HELLO,
                                        &tmpl->server_hello_extension);
            break;
        case CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                                        &tmpl->encrypted_extension);
            break;
        case CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                                        &tmpl->certificate_request_extension);
            break;
        case CTLS_TMPL_TYPE_KNOWN_CERTIFICATES:
            for (int i = 0; i < sizeof(tmpl->known_certificates); i++) {
                result = ctls_write_u8(buffer,
                              offset,
                              tmpl->known_certificates.entries[i].certificate_id,
                              CTLS_SIZE_WIRE_BUFFER);
                if (result != CTLS_STATUS_SUCCESS) return result;
                result = ctls_write_bytes(buffer,
                                 offset,
                                 tmpl->known_certificates.entries[i].certificate_length,
                                 tmpl->known_certificates.entries[i].certificate,
                                 CTLS_SIZE_WIRE_BUFFER);
                if (result != CTLS_STATUS_SUCCESS) return result;
            }
            break;
        case CTLS_TMPL_TYPE_FINISHED_SIZE:
            result = ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_FINISHED_SIZE,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u32(buffer, offset, sizeof(tmpl->finished_size),
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, tmpl->finished_size, CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            break;
        default: return CTLS_STATUS_TMPL_UNKNOWN_ELEMENT;
    }
    return CTLS_STATUS_SUCCESS;
}

/*
 * Canonical byte form of the active template:
 *
 *     content_type(u8, CTLS_RECD_CONTENT_TYPE_TEMPLATE)
 *     | body_length(u24, backfilled)
 *     | ctls_version(u8)
 *     | element_length(u32, backfilled)
 *     | template elements (currently PROFILE_ID only)
 *
 * Both peers must derive identical bytes from their template copies — this
 * form is what makes the template hashable/identifiable.
 */
ctls_status_t ctls_template_to_wire(uint8_t *buffer,
                                    ctls_size_t const limit,
                                    ctls_size_t *bytes_written) {
    ctls_template_t const *tmpl = ctls_template_get();
    if (!tmpl) return CTLS_STATUS_TMPL_TO_WIRE_NULL;
    CTLS_CHECK_NULL_OFFSET(bytes_written);

    ctls_size_t offset = 0, template_body_length;
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_write_u8(buffer, &offset, CTLS_RECD_CONTENT_TYPE_TEMPLATE, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;

    template_body_length = offset;
    offset += 3;

    result = ctls_write_u8(buffer, &offset, CTLS_VERSION, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_size_t template_element_length = offset;
    offset += 4;

    result = ctls_template_element_to_wire(buffer, &offset, tmpl, CTLS_TMPL_TYPE_PROFILE_ID);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u32(buffer, &template_element_length, offset - template_element_length,
                            limit);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_write_u24(buffer, &template_body_length, offset - template_body_length, limit);
    if (result != CTLS_STATUS_SUCCESS) return result;

    *bytes_written = offset;
    return CTLS_STATUS_SUCCESS;
}
