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
            return CTLS_ERR_SUCCESS;
        }
        default: {
            context->template = NULL;
            return CTLS_ERR_TMPL_UNKNOWN_PROFILE;
        }
    }
}

ctls_status_t ctls_tmpl_extension_to_wire(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          ctls_tmpl_extension_t const *extensions) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(extensions);

    ctls_size_t predefined_extensions_length_offset = *offset;
    (*offset) += 2;

    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(extensions->predefined_extensions.server_name.data,
                                           extensions->predefined_extensions.server_name.length)) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SERVER_NAME);
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.server_name.length);
        ctls_write_bytes(buffer, offset, extensions->predefined_extensions.server_name.length,
                         extensions->predefined_extensions.server_name.data);
    }

    if (extensions->predefined_extensions.maximum_fragment_length != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.maximum_fragment_length));
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.maximum_fragment_length);
    }

    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(extensions->predefined_extensions.certificate_status_request.data,
                                           extensions->predefined_extensions.certificate_status_request.length)) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_STATUS_REQUEST);
        ctls_write_u16(buffer, offset,
                       extensions->predefined_extensions.certificate_status_request.length);
        ctls_write_bytes(buffer, offset,
                         extensions->predefined_extensions.certificate_status_request.length,
                         extensions->predefined_extensions.certificate_status_request.data);
    }

    if (extensions->predefined_extensions.heartbeat_mode != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_HEARTBEAT);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.heartbeat_mode));
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.heartbeat_mode);
    }

    if (CTLS_IS_TEMPLATE_BYTES_INITIALIZED(extensions->predefined_extensions.alpn.data,
                                           extensions->predefined_extensions.alpn.length)) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.alpn.length);
        ctls_write_bytes(buffer, offset, extensions->predefined_extensions.alpn.length,
                         extensions->predefined_extensions.alpn.data);
    }

    if (extensions->predefined_extensions.client_certificate_type != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.client_certificate_type));
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.client_certificate_type);
    }

    if (extensions->predefined_extensions.server_certificate_type != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.server_certificate_type));
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.server_certificate_type);
    }

    if (extensions->predefined_extensions.psk_key_exchange_modes != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.psk_key_exchange_modes));
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.psk_key_exchange_modes);
    }

    if (extensions->predefined_extensions.post_handshake_auth != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.post_handshake_auth));
        ctls_write_u8(buffer, offset, extensions->predefined_extensions.post_handshake_auth);
    }

    if (extensions->predefined_extensions.signature_algorithm_cert != 0) {
        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT);
        ctls_write_u16(buffer, offset,
                       sizeof(extensions->predefined_extensions.signature_algorithm_cert));
        ctls_write_u16(buffer, offset, extensions->predefined_extensions.signature_algorithm_cert);
    }

    ctls_write_u16(buffer, &predefined_extensions_length_offset,
                   *offset - predefined_extensions_length_offset);

    ctls_size_t expected_extensions_length = *offset;
    *offset += 2;
    for (size_t i = 0;
         i < sizeof(extensions->expected_extensions) / sizeof(extensions->expected_extensions[0]);
         i++) {
        if (extensions->expected_extensions[i] == CTLS_EXTN_TYPE_KEY_SHARE)
            return CTLS_ERR_TMPL_INVALID_EXTENSION;

        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
    }
    ctls_write_u16(buffer, &expected_extensions_length,
                   *offset - expected_extensions_length);

    ctls_size_t self_delimited_extensions_length = *offset;
    *offset += 2;
    for (size_t i = 0;
         i < sizeof(extensions->self_delimiting_aextensions) / sizeof(extensions->self_delimiting_aextensions[0]);
         i++) {
        if (extensions->self_delimiting_aextensions[i] == CTLS_EXTN_TYPE_KEY_SHARE)
            return CTLS_ERR_TMPL_INVALID_EXTENSION;

        ctls_write_u16(buffer, offset, CTLS_EXTN_TYPE_KEY_SHARE);
    }
    ctls_write_u16(buffer, &self_delimited_extensions_length,
                   *offset - self_delimited_extensions_length);

    ctls_write_u8(buffer, offset, extensions->allow_additional);

    return CTLS_ERR_SUCCESS;
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
            ctls_write_u32(buffer, offset,
                           sizeof(tmpl->dhe_group.dhe_group) +
                           sizeof(tmpl->dhe_group.key_share_length));
            ctls_write_u16(buffer, offset, tmpl->dhe_group.dhe_group);
            ctls_write_u16(buffer, offset, tmpl->dhe_group.key_share_length);
            break;
        case CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM);
            ctls_write_u32(buffer, offset,
                           sizeof(tmpl->signature_algorithm.signature_algorithm_type) +
                           sizeof(tmpl->signature_algorithm.signature_length));
            ctls_write_u16(buffer, offset, tmpl->signature_algorithm.signature_algorithm_type);
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
            ctls_tmpl_extension_to_wire(buffer, offset, &tmpl->client_hello_extension);
            break;
        case CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer, offset, &tmpl->server_hello_extension);
            break;
        case CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer, offset, &tmpl->encrypted_extension);
            break;
        case CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS);
            ctls_tmpl_extension_to_wire(buffer, offset, &tmpl->certificate_request_extension);
            break;
        case CTLS_TMPL_TYPE_KNOWN_CERTIFICATES:
            for (int i = 0; i < sizeof(tmpl->known_certificates); i++) {
                ctls_write_u8(buffer, offset,
                              tmpl->known_certificates.entries[i].certificate_id);
                ctls_write_bytes(buffer, offset,
                                 tmpl->known_certificates.entries[i].certificate_length,
                                 tmpl->known_certificates.entries[i].certificate);
            }
            break;
        case CTLS_TMPL_TYPE_FINISHED_SIZE:
            ctls_write_u16(buffer, offset, CTLS_TMPL_TYPE_FINISHED_SIZE);
            ctls_write_u32(buffer, offset, sizeof(tmpl->finished_size));
            ctls_write_u16(buffer, offset, tmpl->finished_size);
            break;
        default: return CTLS_ERR_TMPL_UNKNOWN_ELEMENT;
    }
    return CTLS_ERR_SUCCESS;
}

ctls_status_t ctls_template_to_wire(uint8_t *buffer) {
    ctls_template_t const *tmpl = ctls_template_get();
    if (!tmpl) return CTLS_ERR_TMPL_NULL;

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

    return CTLS_ERR_SUCCESS;
}