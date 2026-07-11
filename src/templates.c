//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#include "ctls/templates.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#define JSMN_STATIC
#include "jsmn.h"

/*
 * Template handling. See templates.h for what a template is and config.h
 * for the built-in template's values. Comments here describe the exact byte
 * layouts of the template's canonical wire form.
 */

/* Mutable storage for the template ctls_template_set loads from JSON —
 * context->template points here. template.json is the sole source of
 * truth; fields it doesn't cover (finished_size, mutual_auth,
 * handshake_framing, certificate_request_extension) are left at zero. */
static ctls_template_t ctls_template_json_storage;

/*
 * Load the active profile from context->template_path (set by
 * ctls_template_path_set, called from ctls_context_init before this) and
 * parse it via ctls_template_from_json into ctls_template_json_storage.
 */
ctls_status_t ctls_template_set(ctls_context_t *context) {
    CTLS_CHECK_NULL_STRUCT(context);

    context->template = NULL;

    if (context->template_path == NULL) return CTLS_STATUS_TMPL_PATH_NULL;

    FILE *file = fopen(context->template_path, "rb");
    if (file == NULL) return CTLS_STATUS_TMPL_JSON_FILE_NOT_FOUND;

    static uint8_t json_buffer[CTLS_SIZE_JSON_BUFFER];
    size_t const bytes_read = fread(json_buffer, 1, sizeof(json_buffer), file);
    fclose(file);

    memset(&ctls_template_json_storage, 0, sizeof(ctls_template_json_storage));
    ctls_status_t const result = ctls_template_from_json(
            json_buffer, (ctls_size_t) bytes_read, &ctls_template_json_storage);
    if (result != CTLS_STATUS_SUCCESS) return result;

    context->template = &ctls_template_json_storage;
    return CTLS_STATUS_SUCCESS;
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
 *     content_type(u8, CTLS_HSMG_TYPE_TEMPLATE)
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

    result = ctls_write_u8(buffer, &offset, CTLS_HSMG_TYPE_TEMPLATE, limit);
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

/*
 * JSON profile loading (ctls_template_from_json, declared in templates.h).
 * Uses jsmn (JSMN_STATIC above pulls its implementation in as file-local,
 * zero dynamic allocation — see include/jsmn.h). jsmn only tokenizes; the
 * static helpers below do the object/array walking and value conversion.
 */

struct ctls_tmpl_json_name_value {
    char const *name;
    uint16_t value;
};

static struct ctls_tmpl_json_name_value const CTLS_TMPL_JSON_CIPHER_SUITES[] = {
        {"TLS_AES_128_GCM_SHA256", CTLS_HSMG_CIPHER_SUITE_AES_128_GCM_SHA256},
        {"TLS_AES_256_GCM_SHA384", CTLS_HSMG_CIPHER_SUITE_AES_256_GCM_SHA384},
        {"TLS_CHACHA20_POLY1305_SHA256", CTLS_HSMG_CIPHER_SUITE_CHACHA20_POLY1305_SHA256},
        {"TLS_AES_128_CCM_SHA256", CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_SHA256},
        {"TLS_AES_128_CCM_8_SHA256", CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_8_SHA256},
};

static struct ctls_tmpl_json_name_value const CTLS_TMPL_JSON_DHE_GROUPS[] = {
        {"secp256r1", CTLS_EXTN_DHE_GROUP_SECP256R1},
        {"secp384r1", CTLS_EXTN_DHE_GROUP_SECP384R1},
        {"secp521r1", CTLS_EXTN_DHE_GROUP_SECP521R1},
        {"x25519", CTLS_EXTN_DHE_GROUP_X25519},
        {"x448", CTLS_EXTN_DHE_GROUP_X448},
        {"ffdhe2048", CTLS_EXTN_DHE_GROUP_FFDHE2048},
        {"ffdhe3072", CTLS_EXTN_DHE_GROUP_FFDHE3072},
        {"ffdhe4096", CTLS_EXTN_DHE_GROUP_FFDHE4096},
};

static struct ctls_tmpl_json_name_value const CTLS_TMPL_JSON_SIGNATURE_SCHEMES[] = {
        {"rsa_pkcs1_sha256", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256},
        {"rsa_pkcs1_sha384", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA384},
        {"rsa_pkcs1_sha512", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA512},
        {"ecdsa_secp256r1_sha256", CTLS_EXTN_SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256},
        {"ecdsa_secp384r1_sha384", CTLS_EXTN_SIGNATURE_ALGORITHM_ECDSA_SECP384R1_SHA384},
        {"ecdsa_secp521r1_sha512", CTLS_EXTN_SIGNATURE_ALGORITHM_ECDSA_SECP521R1_SHA512},
        {"rsa_pss_rsae_sha256", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_RSAE_SHA256},
        {"rsa_pss_rsae_sha384", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_RSAE_SHA384},
        {"rsa_pss_rsae_sha512", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_RSAE_SHA512},
        {"ed25519", CTLS_EXTN_SIGNATURE_ALGORITHM_ED25519},
        {"ed448", CTLS_EXTN_SIGNATURE_ALGORITHM_ED448},
        {"rsa_pss_pss_sha256", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_PSS_SHA256},
        {"rsa_pss_pss_sha384", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_PSS_SHA384},
        {"rsa_pss_pss_sha512", CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_PSS_SHA512},
};

static struct ctls_tmpl_json_name_value const CTLS_TMPL_JSON_EXTENSION_TYPES[] = {
        {"server_name", CTLS_EXTN_TYPE_SERVER_NAME},
        {"max_fragment_length", CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH},
        {"status_request", CTLS_EXTN_TYPE_STATUS_REQUEST},
        {"supported_groups", CTLS_EXTN_TYPE_SUPPORTED_GROUPS},
        {"signature_algorithms", CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS},
        {"use_srtp", CTLS_EXTN_TYPE_USE_SRTP},
        {"heartbeat", CTLS_EXTN_TYPE_HEARTBEAT},
        {"application_layer_protocol_negotiation",
         CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION},
        {"signed_certificate_timestamp", CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP},
        {"client_certificate_type", CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE},
        {"server_certificate_type", CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE},
        {"padding", CTLS_EXTN_TYPE_PADDING},
        {"pre_shared_key", CTLS_EXTN_TYPE_PRE_SHARED_KEY},
        {"early_data", CTLS_EXTN_TYPE_EARLY_DATA},
        {"supported_versions", CTLS_EXTN_TYPE_SUPPORTED_VERSIONS},
        {"cookie", CTLS_EXTN_TYPE_COOKIE},
        {"psk_key_exchange_modes", CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES},
        {"certificate_authorities", CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES},
        {"oid_filters", CTLS_EXTN_TYPE_OID_FILTERS},
        {"post_handshake_auth", CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH},
        {"signature_algorithms_cert", CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT},
        {"key_share", CTLS_EXTN_TYPE_KEY_SHARE},
};

/* Total token count of the subtree rooted at tokens[index] (self + every descendant). */
static ctls_size_t ctls_tmpl_json_token_span(jsmntok_t const *tokens, int const index) {
    jsmntok_t const *tok = &tokens[index];
    ctls_size_t span = 1;

    if (tok->type == JSMN_OBJECT) {
        int child = index + 1;
        for (int i = 0; i < tok->size; i++) {
            child += 1; /* key string token */
            ctls_size_t const value_span = ctls_tmpl_json_token_span(tokens, child);
            child += (int) value_span;
            span += 1U + value_span;
        }
    } else if (tok->type == JSMN_ARRAY) {
        int child = index + 1;
        for (int i = 0; i < tok->size; i++) {
            ctls_size_t const value_span = ctls_tmpl_json_token_span(tokens, child);
            child += (int) value_span;
            span += value_span;
        }
    }
    return span;
}

/*
 * Index of the value token for key inside object tokens[object_index], or
 * -1 if the object has no such key. object_index must be a JSMN_OBJECT.
 */
static int ctls_tmpl_json_object_get(char const *json,
                                     jsmntok_t const *tokens,
                                     int const object_index,
                                     char const *key) {
    jsmntok_t const *object = &tokens[object_index];
    int const key_length = (int) strlen(key);
    int child = object_index + 1;

    for (int i = 0; i < object->size; i++) {
        jsmntok_t const *key_token = &tokens[child];
        int const token_length = key_token->end - key_token->start;
        if (token_length == key_length &&
            strncmp(json + key_token->start, key, (size_t) key_length) == 0)
            return child + 1;

        int const value_index = child + 1;
        child = value_index + (int) ctls_tmpl_json_token_span(tokens, value_index);
    }
    return -1;
}

/* Match a JSMN_STRING token's text against table[].name; *value = table[].value. */
static ctls_status_t ctls_tmpl_json_lookup(struct ctls_tmpl_json_name_value const *table,
                                           ctls_size_t const count,
                                           char const *json,
                                           jsmntok_t const *token,
                                           uint16_t *value) {
    if (token->type != JSMN_STRING) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
    int const token_length = token->end - token->start;

    for (ctls_size_t i = 0; i < count; i++) {
        if ((int) strlen(table[i].name) == token_length &&
            strncmp(json + token->start, table[i].name, (size_t) token_length) == 0) {
            *value = table[i].value;
            return CTLS_STATUS_SUCCESS;
        }
    }
    return CTLS_STATUS_TMPL_JSON_UNKNOWN_ENUM_NAME;
}

/* JSMN_STRING "0x..." -> *value, base 16 (profile/version's wire format). */
static ctls_status_t
ctls_tmpl_json_token_hex_u32(char const *json, jsmntok_t const *token, uint32_t *value) {
    if (token->type != JSMN_STRING) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
    int const token_length = token->end - token->start;
    if (token_length <= 2 || token_length >= 11)
        return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    char text[11];
    memcpy(text, json + token->start, (size_t) token_length);
    text[token_length] = '\0';

    char *end = NULL;
    unsigned long const parsed = strtoul(text, &end, 16);
    if (end == text || *end != '\0') return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    *value = (uint32_t) parsed;
    return CTLS_STATUS_SUCCESS;
}

/* JSMN_PRIMITIVE decimal number -> *value. */
static ctls_status_t
ctls_tmpl_json_token_u32(char const *json, jsmntok_t const *token, uint32_t *value) {
    if (token->type != JSMN_PRIMITIVE) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
    int const token_length = token->end - token->start;
    if (token_length <= 0 || token_length >= 11)
        return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    char text[11];
    memcpy(text, json + token->start, (size_t) token_length);
    text[token_length] = '\0';

    char *end = NULL;
    unsigned long const parsed = strtoul(text, &end, 10);
    if (end == text || *end != '\0') return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    *value = (uint32_t) parsed;
    return CTLS_STATUS_SUCCESS;
}

/* JSMN_STRING key "01".."ff" (bare hex byte, no "0x" prefix) -> *value. */
static ctls_status_t
ctls_tmpl_json_key_hex_u8(char const *json, jsmntok_t const *token, uint8_t *value) {
    int const token_length = token->end - token->start;
    if (token_length <= 0 || token_length > 2) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    char text[3];
    memcpy(text, json + token->start, (size_t) token_length);
    text[token_length] = '\0';

    char *end = NULL;
    unsigned long const parsed = strtoul(text, &end, 16);
    if (end == text || *end != '\0') return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    *value = (uint8_t) parsed;
    return CTLS_STATUS_SUCCESS;
}

/* JSMN_STRING even-length hex text (no "0x" prefix) -> raw bytes in out. */
static ctls_status_t ctls_tmpl_json_token_hex_bytes(char const *json,
                                                    jsmntok_t const *token,
                                                    uint8_t *out,
                                                    ctls_size_t const capacity,
                                                    ctls_size_t *out_length) {
    if (token->type != JSMN_STRING) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
    int const token_length = token->end - token->start;
    if (token_length < 0 || (token_length % 2) != 0)
        return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    ctls_size_t const byte_length = (ctls_size_t) (token_length / 2);
    if (byte_length > capacity) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    for (ctls_size_t i = 0; i < byte_length; i++) {
        char pair[3] = {json[token->start + (int) (i * 2U)],
                        json[token->start + (int) (i * 2U) + 1],
                        '\0'};
        char *end = NULL;
        unsigned long const value = strtoul(pair, &end, 16);
        if (end != pair + 2) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
        out[i] = (uint8_t) value;
    }

    *out_length = byte_length;
    return CTLS_STATUS_SUCCESS;
}

/* Decoded storage for known_certificates entries parsed from JSON — the
 * struct's certificate field is a pointer, so the decoded DER bytes need
 * somewhere persistent to live. */
static uint8_t ctls_tmpl_json_cert_storage[CTLS_COUNT_KNOWN_CERTIFICATES]
                                          [CTLS_SIZE_KNOWN_CERTIFICATE_MAX];

/*
 * Parse knownCertificates: a JSON object keyed by certificate_id (bare hex
 * byte, e.g. "01"), each value a hex-encoded DER certificate — not an
 * array, since the object key already carries the id (no separate
 * certificateId field to parse). Optional: absent, leave
 * known_certificates untouched (whatever ctls_template_set seeded it
 * with).
 */
static ctls_status_t
ctls_tmpl_json_known_certificates(char const *json,
                                  jsmntok_t const *tokens,
                                  int const root_index,
                                  ctls_tmpl_known_certificates_t *known_certificates) {
    int const block_index =
            ctls_tmpl_json_object_get(json, tokens, root_index, "knownCertificates");
    if (block_index < 0) return CTLS_STATUS_SUCCESS;
    if (tokens[block_index].type != JSMN_OBJECT)
        return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    ctls_size_t const capacity =
            sizeof(known_certificates->entries) / sizeof(known_certificates->entries[0]);
    if ((ctls_size_t) tokens[block_index].size > capacity)
        return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    int child = block_index + 1;
    for (int i = 0; i < tokens[block_index].size; i++) {
        jsmntok_t const *key_token = &tokens[child];
        if (key_token->type != JSMN_STRING) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

        uint8_t certificate_id = 0;
        ctls_status_t result =
                ctls_tmpl_json_key_hex_u8(json, key_token, &certificate_id);
        if (result != CTLS_STATUS_SUCCESS) return result;

        int const value_index = child + 1;
        ctls_size_t certificate_length = 0;
        result = ctls_tmpl_json_token_hex_bytes(json,
                                                &tokens[value_index],
                                                ctls_tmpl_json_cert_storage[i],
                                                CTLS_SIZE_KNOWN_CERTIFICATE_MAX,
                                                &certificate_length);
        if (result != CTLS_STATUS_SUCCESS) return result;

        known_certificates->entries[i].certificate_id = certificate_id;
        known_certificates->entries[i].certificate = ctls_tmpl_json_cert_storage[i];
        known_certificates->entries[i].certificate_length = (uint16_t) certificate_length;

        child = value_index + (int) ctls_tmpl_json_token_span(tokens, value_index);
    }
    return CTLS_STATUS_SUCCESS;
}

/*
 * Parse one per-message extension block (clientHelloExtensions,
 * serverHelloExtensions, encryptedExtensions): expectedExtensions[] and
 * allowAdditional. Absent block, or absent field within a present block,
 * is left untouched (optional — see templates.h doc comment).
 */
static ctls_status_t ctls_tmpl_json_extension_block(char const *json,
                                                    jsmntok_t const *tokens,
                                                    int const root_index,
                                                    char const *key,
                                                    ctls_tmpl_extension_t *extension) {
    int const block_index = ctls_tmpl_json_object_get(json, tokens, root_index, key);
    if (block_index < 0) return CTLS_STATUS_SUCCESS;
    if (tokens[block_index].type != JSMN_OBJECT)
        return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

    int const allow_index =
            ctls_tmpl_json_object_get(json, tokens, block_index, "allowAdditional");
    if (allow_index >= 0) {
        if (tokens[allow_index].type != JSMN_PRIMITIVE)
            return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
        extension->allow_additional = (json[tokens[allow_index].start] == 't') ? 1U : 0U;
    }

    int const expected_index =
            ctls_tmpl_json_object_get(json, tokens, block_index, "expectedExtensions");
    if (expected_index >= 0) {
        if (tokens[expected_index].type != JSMN_ARRAY)
            return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

        ctls_size_t const capacity = sizeof(extension->expected_extensions) /
                                     sizeof(extension->expected_extensions[0]);
        if ((ctls_size_t) tokens[expected_index].size > capacity)
            return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;

        int child = expected_index + 1;
        for (int i = 0; i < tokens[expected_index].size; i++) {
            uint16_t value = 0;
            ctls_status_t const result = ctls_tmpl_json_lookup(
                    CTLS_TMPL_JSON_EXTENSION_TYPES,
                    sizeof(CTLS_TMPL_JSON_EXTENSION_TYPES) /
                            sizeof(CTLS_TMPL_JSON_EXTENSION_TYPES[0]),
                    json,
                    &tokens[child],
                    &value);
            if (result != CTLS_STATUS_SUCCESS) return result;
            extension->expected_extensions[i] = (ctls_extn_type_t) value;
            child += (int) ctls_tmpl_json_token_span(tokens, child);
        }
    }
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_template_from_json(uint8_t const *json,
                                      ctls_size_t const json_length,
                                      ctls_template_t *tmpl) {
    CTLS_CHECK_NULL_BUFFER(json);
    CTLS_CHECK_NULL_STRUCT(tmpl);

    char const *js = (char const *) json;
    jsmntok_t tokens[CTLS_SIZE_JSON_TOKENS];
    jsmn_parser parser;
    jsmn_init(&parser);

    int const token_count =
            jsmn_parse(&parser, js, json_length, tokens, CTLS_SIZE_JSON_TOKENS);
    if (token_count == JSMN_ERROR_NOMEM) return CTLS_STATUS_TMPL_JSON_TOO_MANY_TOKENS;
    if (token_count < 0) return CTLS_STATUS_TMPL_JSON_PARSE_FAILED;
    if (token_count == 0 || tokens[0].type != JSMN_OBJECT)
        return CTLS_STATUS_TMPL_JSON_MALFORMED;

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    int index = 0;
    uint32_t number = 0;
    uint16_t name_value = 0;

    /* profile (hex string) -> profile_id */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "profile");
    if (index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
    result = ctls_tmpl_json_token_hex_u32(js, &tokens[index], &number);
    if (result != CTLS_STATUS_SUCCESS) return result;
    tmpl->profile_id = (uint8_t) number;

    /* version (hex string) -> protocol_version */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "version");
    if (index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
    result = ctls_tmpl_json_token_hex_u32(js, &tokens[index], &number);
    if (result != CTLS_STATUS_SUCCESS) return result;
    tmpl->protocol_version = (ctls_protocol_version_t) number;

    /* ctlsVersion (number, optional) -> ctls_version */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "ctlsVersion");
    if (index >= 0) {
        result = ctls_tmpl_json_token_u32(js, &tokens[index], &number);
        if (result != CTLS_STATUS_SUCCESS) return result;
        tmpl->ctls_version = (uint16_t) number;
    }

    /* random (number) -> random */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "random");
    if (index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
    result = ctls_tmpl_json_token_u32(js, &tokens[index], &number);
    if (result != CTLS_STATUS_SUCCESS) return result;
    tmpl->random = (uint16_t) number;

    /* cipherSuite (name) -> cipher_suite */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "cipherSuite");
    if (index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
    result = ctls_tmpl_json_lookup(CTLS_TMPL_JSON_CIPHER_SUITES,
                                   sizeof(CTLS_TMPL_JSON_CIPHER_SUITES) /
                                           sizeof(CTLS_TMPL_JSON_CIPHER_SUITES[0]),
                                   js,
                                   &tokens[index],
                                   &name_value);
    if (result != CTLS_STATUS_SUCCESS) return result;
    tmpl->cipher_suite = (ctls_cipher_suite_t) name_value;

    /* signatureAlgorithm { signatureScheme, signatureLength } */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "signatureAlgorithm");
    if (index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
    if (tokens[index].type != JSMN_OBJECT) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
    {
        int const scheme_index =
                ctls_tmpl_json_object_get(js, tokens, index, "signatureScheme");
        if (scheme_index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
        result =
                ctls_tmpl_json_lookup(CTLS_TMPL_JSON_SIGNATURE_SCHEMES,
                                      sizeof(CTLS_TMPL_JSON_SIGNATURE_SCHEMES) /
                                              sizeof(CTLS_TMPL_JSON_SIGNATURE_SCHEMES[0]),
                                      js,
                                      &tokens[scheme_index],
                                      &name_value);
        if (result != CTLS_STATUS_SUCCESS) return result;
        tmpl->signature_algorithm.signature_algorithm_type =
                (ctls_signature_scheme_t) name_value;

        int const length_index =
                ctls_tmpl_json_object_get(js, tokens, index, "signatureLength");
        if (length_index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
        result = ctls_tmpl_json_token_u32(js, &tokens[length_index], &number);
        if (result != CTLS_STATUS_SUCCESS) return result;
        tmpl->signature_algorithm.signature_length = (ctls_size_t) number;
    }

    /* dhGroup { groupName, keyShareLength } */
    index = ctls_tmpl_json_object_get(js, tokens, 0, "dhGroup");
    if (index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
    if (tokens[index].type != JSMN_OBJECT) return CTLS_STATUS_TMPL_JSON_FIELD_INVALID;
    {
        int const name_index = ctls_tmpl_json_object_get(js, tokens, index, "groupName");
        if (name_index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
        result = ctls_tmpl_json_lookup(CTLS_TMPL_JSON_DHE_GROUPS,
                                       sizeof(CTLS_TMPL_JSON_DHE_GROUPS) /
                                               sizeof(CTLS_TMPL_JSON_DHE_GROUPS[0]),
                                       js,
                                       &tokens[name_index],
                                       &name_value);
        if (result != CTLS_STATUS_SUCCESS) return result;
        tmpl->dhe_group.dhe_group = (ctls_dhe_group_t) name_value;

        int const length_index =
                ctls_tmpl_json_object_get(js, tokens, index, "keyShareLength");
        if (length_index < 0) return CTLS_STATUS_TMPL_JSON_FIELD_MISSING;
        result = ctls_tmpl_json_token_u32(js, &tokens[length_index], &number);
        if (result != CTLS_STATUS_SUCCESS) return result;
        tmpl->dhe_group.key_share_length = (ctls_size_t) number;
    }

    /* per-message extension blocks (optional) */
    result = ctls_tmpl_json_extension_block(
            js, tokens, 0, "clientHelloExtensions", &tmpl->client_hello_extension);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_tmpl_json_extension_block(
            js, tokens, 0, "serverHelloExtensions", &tmpl->server_hello_extension);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_tmpl_json_extension_block(
            js, tokens, 0, "encryptedExtensions", &tmpl->encrypted_extension);
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* knownCertificates (optional) */
    result = ctls_tmpl_json_known_certificates(js, tokens, 0, &tmpl->known_certificates);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}
