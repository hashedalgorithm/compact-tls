//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#include "ctls/templates.h"

#include "bytes.h"
#include "ctls/ctls.h"

const ctls_template_t ctls_template_1 = CTLS_TEMPLATE_1_INIT;


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

    ctls_write_u16(buffer,
                   &predefined_extensions_length_offset,
                   *offset - predefined_extensions_length_offset);

    ctls_size_t expected_extensions_length = *offset;
    *offset += 2;
    for (size_t i = 0; i < sizeof(extensions->expected_extensions) / sizeof(extensions->
                           expected_extensions[0]); i++) {
        if (extensions->expected_extensions[i] == CTLS_EXTN_TYPE_KEY_SHARE)
            return CTLS_STATUS_TMPL_INVALID_EXTENSION;

        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
    }
    ctls_write_u16(buffer,
                   &expected_extensions_length,
                   *offset - expected_extensions_length);

    ctls_size_t self_delimited_extensions_length = *offset;
    *offset += 2;
    for (size_t i = 0; i < sizeof(extensions->self_delimiting_aextensions) / sizeof(
                           extensions->self_delimiting_aextensions[0]); i++) {
        if (extensions->self_delimiting_aextensions[i] == CTLS_EXTN_TYPE_KEY_SHARE)
            return CTLS_STATUS_TMPL_INVALID_EXTENSION;

        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
    }
    ctls_write_u16(buffer,
                   &self_delimited_extensions_length,
                   *offset - self_delimited_extensions_length);

    ctls_write_u8(buffer, offset, extensions->allow_additional);

    return CTLS_STATUS_SUCCESS;
}


ctls_status_t ctls_template_element_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_template_t const *tmpl,
                                            ctls_tmpl_type_t const type) {
    switch (type) {
        case CTLS_TMPL_TYPE_PROFILE_ID:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_PROFILE_ID);
            ctls_write_u32(buffer, offset, sizeof(uint8_t) + sizeof(tmpl->profile_id));
            ctls_write_u8(buffer, offset, sizeof(tmpl->profile_id));
            ctls_write_u8(buffer, offset, tmpl->profile_id);
            break;
        case CTLS_TMPL_TYPE_VERSION:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_VERSION);
            ctls_write_u32(buffer, offset, sizeof(tmpl->protocol_version));
            ctls_write_u16(buffer, offset, tmpl->protocol_version);
            break;
        case CTLS_TMPL_TYPE_CIPHER_SUITE:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CIPHER_SUITE);
            ctls_write_u32(buffer, offset, sizeof(tmpl->cipher_suite));
            ctls_write_u16(buffer, offset, tmpl->cipher_suite);
            break;
        case CTLS_TMPL_TYPE_DH_GROUP:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_DH_GROUP);
            ctls_write_u32(buffer,
                           offset,
                           sizeof(tmpl->dhe_group.dhe_group) + sizeof(tmpl->dhe_group.
                               key_share_length));
            ctls_write_u16(buffer, offset, tmpl->dhe_group.dhe_group);
            ctls_write_u16(buffer, offset, tmpl->dhe_group.key_share_length);
            break;
        case CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM);
            ctls_write_u32(buffer,
                           offset,
                           sizeof(tmpl->signature_algorithm.signature_algorithm_type) +
                           sizeof(tmpl->signature_algorithm.signature_length));
            ctls_write_u16(buffer,
                           offset,
                           tmpl->signature_algorithm.signature_algorithm_type);
            ctls_write_u16(buffer, offset, tmpl->signature_algorithm.signature_length);
            break;
        case CTLS_TMPL_TYPE_RANDOM:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_RANDOM);
            ctls_write_u32(buffer, offset, sizeof(tmpl->random));
            ctls_write_u16(buffer, offset, tmpl->random);
            break;
        case CTLS_TMPL_TYPE_MUTUAL_AUTH:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_MUTUAL_AUTH);
            ctls_write_u32(buffer, offset, sizeof(tmpl->mutual_auth));
            ctls_write_u16(buffer, offset, tmpl->mutual_auth);
            break;
        case CTLS_TMPL_TYPE_HANDSHAKE_FRAMING:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_HANDSHAKE_FRAMING);
            ctls_write_u32(buffer, offset, sizeof(tmpl->handshake_framing));
            ctls_write_u16(buffer, offset, tmpl->handshake_framing);
            break;
        case CTLS_TMPL_TYPE_CLIENT_HELLO_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CLIENT_HELLO_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_CLIENT_HELLO,
                                        &tmpl->client_hello_extension);
            break;
        case CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_SERVER_HELLO,
                                        &tmpl->server_hello_extension);
            break;
        case CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                                        &tmpl->encrypted_extension);
            break;
        case CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer,
                                        offset,
                                        CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                                        &tmpl->certificate_request_extension);
            break;
        case CTLS_TMPL_TYPE_KNOWN_CERTIFICATES:
            for (int i = 0; i < sizeof(tmpl->known_certificates); i++) {
                ctls_write_u8(buffer,
                              offset,
                              tmpl->known_certificates.entries[i].certificate_id);
                ctls_write_bytes(buffer,
                                 offset,
                                 tmpl->known_certificates.entries[i].certificate_length,
                                 tmpl->known_certificates.entries[i].certificate);
            }
            break;
        case CTLS_TMPL_TYPE_FINISHED_SIZE:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_FINISHED_SIZE);
            ctls_write_u32(buffer, offset, sizeof(tmpl->finished_size));
            ctls_write_u16(buffer, offset, tmpl->finished_size);
            break;
        default: return CTLS_STATUS_TMPL_UNKNOWN_ELEMENT;
    }
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_template_to_wire(uint8_t *buffer) {
    ctls_template_t const *tmpl = ctls_template_get();
    if (!tmpl) return CTLS_STATUS_TMPL_NULL;

    ctls_size_t offset = 0, template_body_length;

    ctls_write_u8(buffer, &offset, CTLS_RECD_CONTENT_TYPE_TEMPLATE);

    template_body_length = offset;
    offset += 3;

    ctls_write_u8(buffer, &offset, CTLS_VERSION);

    ctls_size_t template_element_length = offset;
    offset += 4;

    ctls_template_element_to_wire(buffer, &offset, tmpl, CTLS_TMPL_TYPE_PROFILE_ID);
    ctls_write_u32(buffer, &template_element_length, offset - template_element_length);

    ctls_write_u24(buffer, &template_body_length, offset - template_body_length);

    return CTLS_STATUS_SUCCESS;
}
