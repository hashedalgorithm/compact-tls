//
// Created by SanjayKumar Kumaravelan on 16/04/26.
//

#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#include "ctls/hsmg.h"
#include "ctls/templates.h"

/*
 * Handshake message serialization. See hsmg.h for the API overview.
 * Comments here give the exact byte layouts of both wire formats:
 *
 *   DEFAULT          — compact cTLS bytes that go on the wire. Template-
 *                      pinned values and TLS 1.3 legacy fields are omitted.
 *   TRANSCRIPT_HASH  — the message re-expanded into RFC 8446 §4 Handshake
 *                      syntax (msg_type(u8) | length(u24) | body), hashed
 *                      into the transcript but never sent.
 */

/*
 * Build ClientHello (RFC 8446 §4.1.2) from the template: fresh random of
 * template->random bytes (stored in hshk_data->client_random), pinned
 * cipher suite and protocol version, legacy_session_id and
 * legacy_compression_methods zeroed (cTLS drops them; TLS 1.3 already calls
 * them legacy), extensions via ctls_extn_client_hello_create.
 */
ctls_status_t ctls_hsmg_client_hello_create(ctls_hsmg_client_hello_t *client_hello) {
    ctls_template_t const *template = ctls_template_get();
    ctls_crypto_t const *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(client_hello);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t const result = ctls_random_generate(hshk_data->client_random,
                                                      &client_hello->random.buffer_length,
                                                      template->random);
    client_hello->random.buffer = hshk_data->client_random;

    if (result != CTLS_STATUS_SUCCESS) return result;

    client_hello->cipher_suite = template->cipher_suite;
    client_hello->protocol_version = template->protocol_version;
    client_hello->legacy_session_id = 0x00;
    client_hello->legacy_compression_methods = 0x00;

    return ctls_extn_client_hello_create(&client_hello->extensions);
}


/*
 * Parse a compact ClientHello body (server-side receive).
 *
 *     body_length(u16, consumed but not stored)
 *     | message_type(u8)
 *     | sequence_number(u16) — CTLS_TRANSPORT_UNRELIABLE only (draft §2.3.1
 *       message_seq), validated against hshk_data->sequence_number; absent
 *       entirely on CTLS_TRANSPORT_RELIABLE builds
 *     | random (template->random bytes, saved to hshk_data->client_random)
 *     | cipher_suite(u16) — only present when template->cipher_suite == 0
 *     | extensions (key_share only; see ctls_extn_client_hello_to_struct)
 */
ctls_status_t ctls_hsmg_client_hello_to_struct(ctls_handshake_message_t *hsmg,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint16_t body_length_u16 = 0;
    uint8_t type_u8 = 0;

    result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &body_length_u16);
    if (result != CTLS_STATUS_SUCCESS) return result; /* body_length — advance past it */

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_CLIENT_HELLO) return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

#if CTLS_TRANSPORT_UNRELIABLE
    /* message_seq (draft §2.3.1, CTLSDatagramHandshake) — reliable builds omit it. */
    result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &hsmg->sequence_number);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (hsmg->sequence_number != hshk_data->sequence_number) return
            CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH;
#endif

    result = ctls_read_bytes(hshk_data->client_random, template->random, buffer, offset,
                             CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    hsmg->handshake_message_body.client_hello.random.buffer = hshk_data->client_random;
    hsmg->handshake_message_body.client_hello.random.buffer_length = template->random;

    if (template->cipher_suite == 0) {
        uint16_t cipher_suite_u16 = 0;
        result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &cipher_suite_u16);
        if (result != CTLS_STATUS_SUCCESS) return result;
        hsmg->handshake_message_body.client_hello.cipher_suite = cipher_suite_u16;
    } else {
        hsmg->handshake_message_body.client_hello.cipher_suite = template->cipher_suite;
    }

    hsmg->handshake_message_body.client_hello.protocol_version = template->
            protocol_version;
    hsmg->handshake_message_body.client_hello.legacy_session_id = 0x00;
    hsmg->handshake_message_body.client_hello.legacy_compression_methods = 0x00;

    return ctls_extn_client_hello_to_struct(&hsmg->handshake_message_body.client_hello.
                                            extensions,
                                            buffer,
                                            offset);
}

/*
 * Emit ClientHello.
 *
 * DEFAULT (compact cTLS):
 *
 *     body_length(u16, backfilled)
 *     | message_type(u8) | sequence_number(u16), CTLS_TRANSPORT_UNRELIABLE only
 *     | random (template->random bytes, no length)
 *     | cipher_suites block — only when the template does NOT pin a suite
 *     | extensions (key_share bytes only, see extensions.c)
 *
 *   legacy_session_id / legacy_compression_methods never appear.
 *
 * TRANSCRIPT_HASH (RFC 8446 §4 + §4.1.2 reconstruction):
 *
 *     msg_type(u8) | length(u24, backfilled)
 *     | legacy_version(u16) = 0x0303   ("MUST be set to 0x0303")
 *     | random
 *     | session_id_length(u8) | legacy_session_id(u8)
 *     | cipher_suites_length(u16) | cipher_suite(u16)
 *     | compression_length(u8) | legacy_compression_methods(u8)
 *     | extensions in TLS 1.3 framing
 */
ctls_status_t ctls_hsmg_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_handshake_message_t const *hsmg,
                                             ctls_wire_format_t const wire_format) {
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(offset);
    CTLS_CHECK_NULL_STRUCT(hsmg);

    ctls_size_t body_start = *offset;
    ctls_status_t result = CTLS_STATUS_SUCCESS;
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        *offset += 2; /* reserve 2 bytes for body length (u16), backfilled below */

        result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_CLIENT_HELLO,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
#if CTLS_TRANSPORT_UNRELIABLE
        /* message_seq (draft §2.3.1, CTLSDatagramHandshake) — reliable builds omit it. */
        result = ctls_write_u16(buffer, offset, hsmg->sequence_number, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
#endif

        result = ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer,
                         CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if (template->cipher_suite == 0) {
            result = ctls_write_u16(buffer,
                           offset,
                           sizeof(hsmg->handshake_message_body.client_hello.
                               cipher_suite),
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer, offset, CTLS_DEFAULT_SENTINEL,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        result = ctls_extn_client_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.client_hello.extensions,
            wire_format);

        ctls_status_t const length_result = ctls_write_u16(buffer, &body_start,
                                                            *offset - body_start,
                                                            CTLS_SIZE_WIRE_BUFFER);
        if (length_result != CTLS_STATUS_SUCCESS) return length_result;

        return result;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_CLIENT_HELLO,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        ctls_size_t hsmg_body_length_offset = *offset;
        *offset += 3;

        result = ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer,
                         CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.client_hello.
                          legacy_session_id),
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.client_hello.legacy_session_id,
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u16(buffer,
                       offset,
                       sizeof(hsmg->handshake_message_body.client_hello.cipher_suite),
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u16(buffer,
                       offset,
                       hsmg->handshake_message_body.client_hello.cipher_suite,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.client_hello.
                          legacy_compression_methods),
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.client_hello.
                      legacy_compression_methods,
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_extn_client_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.client_hello.extensions,
            wire_format);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u24(buffer,
                       &hsmg_body_length_offset,
                       *offset - hsmg_body_length_offset,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }
    return CTLS_STATUS_HSMG_CH_INVALID_WIRE_FORMAT;
}

/*
 * Build a ServerHello from the template (server-side create), mirroring
 * ctls_hsmg_client_hello_create:
 *   - Generate server random of template->random bytes.
 *   - Copy pinned fields (cipher_suite, protocol_version) from template.
 *   - Generate server ephemeral key pair and set key_share extension via
 *     ctls_extn_server_hello_create.
 */
ctls_status_t ctls_hsmg_server_hello_create(ctls_hsmg_server_hello_t *server_hello) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(server_hello);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(hshk_data);

    ctls_size_t random_length = 0;
    ctls_status_t const result = ctls_random_generate(hshk_data->server_random,
                                                      &random_length,
                                                      template->random);
    if (result != CTLS_STATUS_SUCCESS) return result;

    server_hello->random.buffer = hshk_data->server_random;
    server_hello->random.buffer_length = random_length;

    server_hello->cipher_suite = template->cipher_suite;
    server_hello->protocol_version = template->protocol_version;
    server_hello->legacy_session_id_echo = 0;
    server_hello->legacy_compression_method = 0;

    return ctls_extn_server_hello_create(&server_hello->extensions);
}

/*
 * Parse a compact ServerHello:
 *
 *     message_type(u8)
 *     | sequence_number(u16) — CTLS_TRANSPORT_UNRELIABLE only (draft §2.3.1
 *       message_seq), validated against hshk_data->sequence_number; absent
 *       entirely on CTLS_TRANSPORT_RELIABLE builds
 *     | server random (template->random bytes, no length —
 *       saved to hshk_data->server_random)
 *     | cipher_suite(u16)
 *     | 2 bytes skipped
 *     | key_share (raw server public key bytes)
 *
 * protocol_version and the legacy fields are reconstructed from the
 * template — RFC 8446 §4.1.3 values that cTLS never sends.
 */
ctls_status_t ctls_hsmg_server_hello_to_struct(ctls_handshake_message_t *hsmg,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset) {
    ctls_template_t const *template = ctls_template_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(hshk_data);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t type_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_SERVER_HELLO) return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

#if CTLS_TRANSPORT_UNRELIABLE
    /* message_seq (draft §2.3.1, CTLSDatagramHandshake) — reliable builds omit it. */
    result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &hsmg->sequence_number);
    if (result != CTLS_STATUS_SUCCESS) return result;
    if (hsmg->sequence_number != hshk_data->sequence_number) return
            CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH;
#endif

    result = ctls_read_bytes(hshk_data->server_random, template->random, buffer, offset,
                             CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    hsmg->handshake_message_body.server_hello.random.buffer = hshk_data->server_random;
    hsmg->handshake_message_body.server_hello.random.buffer_length = template->random;

    if (template->cipher_suite == 0) {
        uint16_t cipher_suite_u16 = 0;
        result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &cipher_suite_u16);
        if (result != CTLS_STATUS_SUCCESS) return result;
        hsmg->handshake_message_body.server_hello.cipher_suite = cipher_suite_u16;
    } else {
        hsmg->handshake_message_body.server_hello.cipher_suite = template->cipher_suite;
    }

    hsmg->handshake_message_body.server_hello.protocol_version = template->
            protocol_version;
    hsmg->handshake_message_body.server_hello.legacy_compression_method = 0;
    hsmg->handshake_message_body.server_hello.legacy_session_id_echo = 0;

    return ctls_extn_server_hello_to_struct(&hsmg->handshake_message_body.server_hello.
                                            extensions,
                                            buffer,
                                            offset);
}

/*
 * Emit ServerHello, TRANSCRIPT_HASH only (RFC 8446 §4.1.3 reconstruction):
 *
 *     msg_type(u8) | length(u24, backfilled)
 *     | legacy_version(u16) = 0x0303
 *     | random
 *     | session_id_echo_length(u8) | legacy_session_id_echo(u8)
 *     | cipher_suite(u16)
 *     | legacy_compression_length(u8) | legacy_compression_method(u8)
 *     | extensions (supported_versions, key_share)
 *
 * DEFAULT is empty — client build never sends ServerHello.
 */
ctls_status_t ctls_hsmg_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_handshake_message_t const *hsmg,
                                             ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(hsmg);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        /*
         * Compact ServerHello body (matches ctls_hsmg_server_hello_to_struct parse order):
         *     message_type(u8)
         *     | sequence_number(u16), CTLS_TRANSPORT_UNRELIABLE only
         *     | random (template->random bytes)
         *     | cipher_suite(u16) — only when template does not pin a suite
         *     | key_share bytes via ctls_extn_server_hello_to_wire DEFAULT
         */
        result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_SERVER_HELLO,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
#if CTLS_TRANSPORT_UNRELIABLE
        /* message_seq (draft §2.3.1, CTLSDatagramHandshake) — reliable builds omit it. */
        result = ctls_write_u16(buffer, offset, hsmg->sequence_number, CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
#endif
        result = ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.server_hello.random.buffer_length,
                         hsmg->handshake_message_body.server_hello.random.buffer,
                         CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        if (ctls_template_get()->cipher_suite == 0) {
            result = ctls_write_u16(buffer,
                           offset,
                           hsmg->handshake_message_body.server_hello.cipher_suite,
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        return ctls_extn_server_hello_to_wire(buffer,
                                              offset,
                                              &hsmg->handshake_message_body.server_hello.
                                              extensions,
                                              wire_format);
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_SERVER_HELLO,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        ctls_size_t hsmg_body_length_offset = *offset;
        *offset += 3;

        result = ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2,
                                CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.server_hello.random.buffer_length,
                         hsmg->handshake_message_body.server_hello.random.buffer,
                         CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.server_hello.
                          legacy_session_id_echo),
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.server_hello.legacy_session_id_echo,
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u16(buffer,
                       offset,
                       hsmg->handshake_message_body.server_hello.cipher_suite,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.server_hello.
                          legacy_compression_method),
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.server_hello.
                      legacy_compression_method,
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_extn_server_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.server_hello.extensions,
            wire_format);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u24(buffer,
                       &hsmg_body_length_offset,
                       *offset - hsmg_body_length_offset,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_SH_INVALID_WIRE_FORMAT;
}

/*
 * Build EncryptedExtensions (server-side create). All content is
 * template-predefined; reconstruct via ctls_extn_encrypted_extensions_to_struct
 * which pulls values from the template.
 */
ctls_status_t ctls_hsmg_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions) {
    CTLS_CHECK_NULL_STRUCT(encrypted_extensions);

    return ctls_extn_encrypted_extensions_to_struct(&encrypted_extensions->extensions);
}

/*
 * Parse EncryptedExtensions (RFC 8446 §4.3.1). Wire carries only
 * message_type(u8); the whole extension set is template-predefined and
 * reconstructed locally.
 */
ctls_status_t ctls_hsmg_encrypted_extensions_to_struct(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    uint8_t const *buffer,
    ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(encrypted_extensions);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_BUFFER(buffer);

    uint8_t type_u8 = 0;
    ctls_status_t const result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS) return
            CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

    return ctls_extn_encrypted_extensions_to_struct(&encrypted_extensions->extensions);
}

/*
 * Emit EncryptedExtensions, TRANSCRIPT_HASH only (RFC 8446 §4.3.1:
 * "Extension extensions<0..2^16-1>;"):
 *
 *     extensions_length(u16, backfilled) | extensions in TLS 1.3 framing
 */
ctls_status_t ctls_hsmg_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_hsmg_encrypted_extensions_t
                                                     const *encrypted_extensions,
                                                     ctls_wire_format_t const
                                                     wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(encrypted_extensions);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        /* Compact EE: only the message type byte; all extensions are
         * template-pinned and reconstructed by the peer from its template. */
        ctls_status_t const result = ctls_write_u8(buffer, offset,
                                                    CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                                                    CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return ctls_extn_encrypted_extensions_to_wire(buffer,
                                                      offset,
                                                      &encrypted_extensions->extensions,
                                                      wire_format);
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_size_t extensions_length_offset = *offset;

        ctls_status_t const result = ctls_extn_encrypted_extensions_to_wire(buffer,
            offset,
            &encrypted_extensions->extensions,
            wire_format);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_status_t const length_result = ctls_write_u16(buffer,
                       &extensions_length_offset,
                       *offset - extensions_length_offset,
                       CTLS_SIZE_WIRE_BUFFER);
        if (length_result != CTLS_STATUS_SUCCESS) return length_result;
        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_EE_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_certificate_request_create(
    ctls_hsmg_certificate_request_t *certificate_request) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Parse CertificateRequest (RFC 8446 §4.3.2):
 *
 *     message_type(u8)
 *     | context_length(u8) | certificate_request_context bytes
 *
 * The context is saved to hshk_data — RFC 8446 §4.4.2 requires the client's
 * Certificate to echo it. Extensions come from the template.
 */
ctls_status_t ctls_hsmg_certificate_request_to_struct(
    ctls_hsmg_certificate_request_t *certificate_request,
    uint8_t const *buffer,
    ctls_size_t *offset) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(certificate_request);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t type_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_CERTIFICATE_REQUEST) return
            CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

    uint8_t certificate_request_context_length_u8 = 0;
    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER,
                          &certificate_request_context_length_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_size_t const certificate_request_context_length =
            certificate_request_context_length_u8;
    if (certificate_request_context_length > 0) {
        result = ctls_read_bytes(hshk_data->certificate_request_context,
                                 certificate_request_context_length,
                                 buffer,
                                 offset,
                                 CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }

    return ctls_extn_certificate_request_to_struct(&certificate_request->extensions);
}

/*
 * Emit CertificateRequest, TRANSCRIPT_HASH only (RFC 8446 §4.3.2):
 *
 *     msg_type(u8)
 *     | context_length(u8) | certificate_request_context bytes
 *     | extensions_length(u16, backfilled) | extensions
 */
ctls_status_t ctls_hsmg_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_hsmg_certificate_request_t const
                                                    *certificate_request,
                                                    ctls_wire_format_t const
                                                    wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_request);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        // TODO
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_status_t result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                                             CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      certificate_request->certificate_request_context.buffer_length,
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if (certificate_request->certificate_request_context.buffer_length > 0) {
            result = ctls_write_bytes(buffer,
                             offset,
                             certificate_request->certificate_request_context.
                             buffer_length,
                             certificate_request->certificate_request_context.buffer,
                             CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        ctls_size_t extensions_length_offset = *offset;
        result = ctls_extn_certificate_request_to_wire(buffer,
            offset,
            &certificate_request->extensions,
            wire_format);
        if (result != CTLS_STATUS_SUCCESS) return result;

        result = ctls_write_u16(buffer,
                       &extensions_length_offset,
                       *offset - extensions_length_offset,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_CR_INVALID_WIRE_FORMAT;
}

/*
 * Build a Certificate message (RFC 8446 §4.4.2) with the cTLS certificate
 * dictionary: a single entry carrying this build's certificate_id
 * (CTLS_ENTITY_CERTIFICATE_ID) instead of DER, echoing the stored
 * certificate_request_context, plus per-entry extensions (OCSP/SCT) the
 * peer requested.
 */
ctls_status_t ctls_hsmg_certificate_create(ctls_hsmg_certificate_t *certificate,
                                           ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(certificate);
    CTLS_CHECK_NULL(hshk_data);

    certificate->certificate_request_context.buffer = hshk_data->
            certificate_request_context;
    certificate->certificate_request_context.buffer_length =
            CTLS_SIZE_CERTIFICATE_REQUEST_CONTEXT;

    certificate->certificate_entries[0].certificate_id = CTLS_ENTITY_CERTIFICATE_ID;

    certificate->certificate_count = 1;

    return ctls_extn_certificate_create(&certificate->certificate_entries[0].extensions,
                                        entity);
}

/*
 * Parse a Certificate message (RFC 8446 §4.4.2, dictionary-compressed):
 *
 *     message_type(u8)
 *     | context_length(u8) | context bytes (or 1 pad byte when empty)
 *     | certificate_list_length(u24)
 *     | per entry: id_length(u16, skipped) | certificate_id(u16)
 *                | extensions_length(u24)
 *                | extensions (reconstructed from template when non-empty)
 *
 * certificate_id replaces RFC 8446's "opaque cert_data<1..2^24-1>" —
 * the DER is looked up in the template's known_certificates.
 */
ctls_status_t ctls_hsmg_certificate_to_struct(ctls_hsmg_certificate_t *certificate,
                                              uint8_t const *buffer,
                                              ctls_size_t *offset) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(certificate);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t type_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_CERTIFICATE) return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

    uint8_t certificate_request_context_length_u8 = 0;
    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER,
                          &certificate_request_context_length_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_size_t const certificate_request_context_length =
            certificate_request_context_length_u8;
    if (certificate_request_context_length > 0) {
        result = ctls_read_bytes(hshk_data->certificate_request_context,
                                 certificate_request_context_length,
                                 buffer,
                                 offset,
                                 CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
    } else {
        uint8_t discard_u8 = 0;
        result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &discard_u8);
        if (result != CTLS_STATUS_SUCCESS) return result;
    }
    certificate->certificate_request_context.buffer = hshk_data->
            certificate_request_context;
    certificate->certificate_request_context.buffer_length =
            certificate_request_context_length;

    uint32_t certificate_entries_length_u32 = 0;
    result = ctls_read_u24(buffer, offset, CTLS_SIZE_WIRE_BUFFER,
                           &certificate_entries_length_u32);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_size_t const certificate_entries_length = (ctls_size_t) certificate_entries_length_u32;
    ctls_size_t certificate_entries_index = 0;
    ctls_size_t const certificate_entries_absolute_length =
            *offset + certificate_entries_length;

    while (*offset < certificate_entries_absolute_length) {
        *offset += 2; // certificate data length
        result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER,
                               &certificate->certificate_entries[certificate_entries_index].
                               certificate_id);
        if (result != CTLS_STATUS_SUCCESS) return result;

        uint32_t certificate_extensions_length_u32 = 0;
        result = ctls_read_u24(buffer, offset, CTLS_SIZE_WIRE_BUFFER,
                               &certificate_extensions_length_u32);
        if (result != CTLS_STATUS_SUCCESS) return result;
        if (certificate_extensions_length_u32 > 0) {
            result = ctls_extn_certificate_to_struct(&certificate->certificate_entries[
                                                          certificate_entries_index].
                                                      extensions);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }
        certificate_entries_index++;
    }

    certificate->certificate_count = certificate_entries_index;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Emit Certificate, TRANSCRIPT_HASH only (RFC 8446 §4.4.2, dictionary-
 * compressed — both peers reconstruct the same compressed form, so the
 * transcript still matches):
 *
 *     msg_type(u8)
 *     | context_length(u8) | context bytes
 *     | certificate_list_length(u16, backfilled)
 *     | per entry: id_length(u16) | certificate_id(u16)
 *                | extensions_length(u16, backfilled) | extensions
 */
ctls_status_t ctls_hsmg_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_hsmg_certificate_t const *certificate,
                                            ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(certificate);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_CERTIFICATE,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_size_t const certificate_request_context_length = certificate->
                certificate_request_context.buffer_length;
        result = ctls_write_u8(buffer, offset, (uint8_t) certificate_request_context_length,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        if (certificate_request_context_length > 0) {
            result = ctls_write_bytes(buffer,
                             offset,
                             certificate_request_context_length,
                             certificate->certificate_request_context.buffer,
                             CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        } else {
            result = ctls_write_u8(buffer, offset, 0, CTLS_SIZE_WIRE_BUFFER); /* pad byte required by _to_struct */
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        ctls_size_t cert_list_length_offset = *offset;
        *offset += 3; /* u24 placeholder */

        for (uint8_t i = 0; i < certificate->certificate_count; i++) {
            result = ctls_write_u16(buffer,
                           offset,
                           (uint16_t) sizeof(certificate->certificate_entries[i].
                               certificate_id),
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer,
                           offset,
                           certificate->certificate_entries[i].certificate_id,
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            ctls_size_t ext_length_offset = *offset;
            *offset += 3; /* u24 placeholder */
            result = ctls_extn_certificate_to_wire(buffer,
                offset,
                &certificate->certificate_entries[i].extensions,
                wire_format);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u24(buffer, &ext_length_offset, *offset - ext_length_offset - 3,
                                    CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        result = ctls_write_u24(buffer,
                       &cert_list_length_offset,
                       *offset - cert_list_length_offset - 3,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_CERTIFICATE,
                               CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;
        result = ctls_write_u8(buffer,
                      offset,
                      certificate->certificate_request_context.buffer_length,
                      CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        if (certificate->certificate_request_context.buffer_length > 0) {
            result = ctls_write_bytes(buffer,
                             offset,
                             certificate->certificate_request_context.buffer_length,
                             certificate->certificate_request_context.buffer,
                             CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        ctls_size_t certificates_length_offset = *offset;
        *offset += 2;

        for (uint8_t i = 0; i < certificate->certificate_count; i++) {
            result = ctls_write_u16(buffer,
                           offset,
                           sizeof(certificate->certificate_entries[i].certificate_id),
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            result = ctls_write_u16(buffer,
                           offset,
                           certificate->certificate_entries[i].certificate_id,
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
            ctls_size_t certificate_extensions_length_offset = *offset;
            *offset += 2;
            result = ctls_extn_certificate_to_wire(buffer,
                offset,
                &certificate->certificate_entries[i].extensions,
                wire_format);
            if (result != CTLS_STATUS_SUCCESS) return result;

            result = ctls_write_u16(buffer,
                           &certificate_extensions_length_offset,
                           *offset - certificate_extensions_length_offset,
                           CTLS_SIZE_WIRE_BUFFER);
            if (result != CTLS_STATUS_SUCCESS) return result;
        }

        result = ctls_write_u16(buffer,
                       &certificates_length_offset,
                       *offset - certificates_length_offset,
                       CTLS_SIZE_WIRE_BUFFER);
        if (result != CTLS_STATUS_SUCCESS) return result;

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_CERT_INVALID_WIRE_FORMAT;
}

/*
 * Build CertificateVerify (RFC 8446 §4.4.3): scheme pinned by the template,
 * signature computed by ctls_signed_bytes_generate over the §4.4.3 signed
 * content (context string + Transcript-Hash). signature aliases hshk_data's
 * signed-bytes storage for this entity.
 */
ctls_status_t ctls_hsmg_certificate_verify_create(
    ctls_hsmg_certificate_verify_t *certificate_verify,
    ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(certificate_verify);
    CTLS_CHECK_NULL_STRUCT(template);
    CTLS_CHECK_NULL(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_HSMG_INVALID_ENTITY;

    certificate_verify->signature_scheme = template->signature_algorithm.
            signature_algorithm_type;

    ctls_status_t const result = ctls_signed_bytes_generate(entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    certificate_verify->signature = entity == CTLS_ENTITY_CLIENT
                                        ? hshk_data->client_signature
                                        : hshk_data->server_signature;
    certificate_verify->signature_length = CTLS_SIZE_SIGNED_BYTES;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Parse CertificateVerify:
 *
 *     message_type(u8) | signature_scheme(u16)
 *     | signature_length(u16) | signature bytes
 *
 * Signature bytes land in hshk_data's signed-bytes storage for this entity;
 * actual verification happens later in the core ops, not here.
 */
ctls_status_t ctls_hsmg_certificate_verify_to_struct(
    ctls_hsmg_certificate_verify_t *certificate_verify,
    uint8_t const *buffer,
    ctls_size_t *offset,
    ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(certificate_verify);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_OFFSET(hshk_data);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t type_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_CERTIFICATE_VERIFY)
        return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

    uint16_t signature_scheme_u16 = 0;
    result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &signature_scheme_u16);
    if (result != CTLS_STATUS_SUCCESS) return result;
    certificate_verify->signature_scheme = signature_scheme_u16;

    ctls_size_t signed_bytes_length = 0;
    result = ctls_read_u16(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &signed_bytes_length);
    if (result != CTLS_STATUS_SUCCESS) return result;
    uint8_t *sig_buf = entity == CTLS_ENTITY_CLIENT
                           ? hshk_data->client_signature
                           : hshk_data->server_signature;
    result = ctls_read_bytes(sig_buf, signed_bytes_length, buffer, offset, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    certificate_verify->signature_length = (uint8_t) signed_bytes_length;
    certificate_verify->signature = sig_buf;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Emit CertificateVerify, TRANSCRIPT_HASH only (RFC 8446 §4.4.3):
 *
 *     msg_type(u8) | signature_scheme(u16)
 *     | signature_length(u16) | signature bytes
 */
ctls_status_t ctls_hsmg_certificate_verify_to_wire(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_hsmg_certificate_verify_t const *
                                                   certificate_verify) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(certificate_verify);

    ctls_status_t result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_CERTIFICATE_VERIFY,
                                         CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u16(buffer, offset, certificate_verify->signature_scheme,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u16(buffer, offset, certificate_verify->signature_length,
                            CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_bytes(buffer,
                     offset,
                     certificate_verify->signature_length,
                     certificate_verify->signature,
                     CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Build Finished (RFC 8446 §4.4.4): derive this entity's finished key, then
 * verify_data = HMAC(finished_key, Transcript-Hash(...)). verify_data
 * aliases hshk_data storage.
 */
ctls_status_t ctls_hsmg_finished_create(ctls_hsmg_finished_t *finished,
                                        ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(finished);
    CTLS_CHECK_NULL(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_HSMG_INVALID_ENTITY;

    ctls_status_t result = ctls_finished_key_generate(entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_verify_data_generate(entity,
                                       entity == CTLS_ENTITY_CLIENT
                                           ? hshk_data->client_verify_data
                                           : hshk_data->server_verify_data);
    if (result != CTLS_STATUS_SUCCESS) return result;

    finished->verify_data = entity == CTLS_ENTITY_CLIENT
                                ? hshk_data->client_verify_data
                                : hshk_data->server_verify_data;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Parse Finished: message_type(u8) | verify_data[CTLS_SIZE_HASH]. Fixed
 * size, no length field — RFC 8446 §4.4.4:
 * "opaque verify_data[Hash.length];"
 */
ctls_status_t ctls_hsmg_finished_to_struct(ctls_hsmg_finished_t *finished,
                                           uint8_t const *buffer,
                                           ctls_size_t *offset,
                                           ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(finished);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(hshk_data);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t type_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &type_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    ctls_hsmg_type_t const type = type_u8;
    if (type != CTLS_HSMG_TYPE_FINISHED) return CTLS_STATUS_HSMG_INVALID_MSG_TYPE;

    result = ctls_read_bytes(entity == CTLS_ENTITY_CLIENT
                                 ? hshk_data->client_verify_data
                                 : hshk_data->server_verify_data,
                             CTLS_SIZE_HASH,
                             buffer,
                             offset,
                             CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    finished->verify_data = entity == CTLS_ENTITY_CLIENT
                                ? hshk_data->client_verify_data
                                : hshk_data->server_verify_data;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Emit Finished, TRANSCRIPT_HASH only:
 *
 *     msg_type(u8) | verify_data[CTLS_SIZE_HASH]
 */
ctls_status_t ctls_hsmg_finished_to_wire(uint8_t *buffer,
                                         ctls_size_t *offset,
                                         ctls_hsmg_finished_t const *finished) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(finished);


    ctls_status_t result = ctls_write_u8(buffer, offset, CTLS_HSMG_TYPE_FINISHED,
                                         CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_bytes(buffer, offset, CTLS_SIZE_HASH, finished->verify_data,
                              CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_hsmg_server_flight_create(ctls_hsmg_server_flight_t *server_flight) {
    CTLS_CHECK_NULL_STRUCT(server_flight);

    ctls_status_t result =
            ctls_hsmg_encrypted_extensions_create(&server_flight->encrypted_extensions);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_create(&server_flight->certificate,
                                          CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_create(&server_flight->certificate_verify,
                                                 CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_create(&server_flight->finished, CTLS_ENTITY_SERVER);
}

ctls_status_t ctls_hsmg_server_flight_to_struct(ctls_hsmg_server_flight_t *server_flight,
                                                uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(server_flight);
    CTLS_CHECK_NULL_BUFFER(buffer);

    ctls_size_t offset = 0;

    ctls_status_t result =
            ctls_hsmg_encrypted_extensions_to_struct(&server_flight->encrypted_extensions,
                                                     buffer,
                                                     &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_to_struct(&server_flight->certificate,
                                             buffer,
                                             &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_struct(&server_flight->certificate_verify,
                                                    buffer,
                                                    &offset,
                                                    CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_to_struct(&server_flight->finished,
                                        buffer,
                                        &offset,
                                        CTLS_ENTITY_SERVER);
}

ctls_status_t ctls_hsmg_server_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_hsmg_server_flight_t const *
                                              server_flight,
                                              ctls_wire_format_t const wire_format) {
    ctls_status_t result = CTLS_STATUS_SUCCESS;


    result = ctls_hsmg_encrypted_extensions_to_wire(buffer,
                                                    offset,
                                                    &server_flight->encrypted_extensions,
                                                    wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_to_wire(buffer,
                                           offset,
                                           &server_flight->certificate,
                                           wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_wire(buffer,
                                                  offset,
                                                  &server_flight->certificate_verify);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_to_wire(buffer, offset, &server_flight->finished);
}

ctls_status_t ctls_hsmg_client_flight_create(ctls_hsmg_client_flight_t *client_flight) {
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_hsmg_certificate_create(&client_flight->certificate,
                                          CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_create(&client_flight->certificate_verify,
                                                 CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_create(&client_flight->finished, CTLS_ENTITY_CLIENT);
}

ctls_status_t ctls_hsmg_client_flight_to_struct(ctls_hsmg_client_flight_t *client_flight,
                                                uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(client_flight);
    CTLS_CHECK_NULL_BUFFER(buffer);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    ctls_size_t offset = 0;

    result = ctls_hsmg_certificate_to_struct(&client_flight->certificate,
                                             buffer,
                                             &offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_struct(&client_flight->certificate_verify,
                                                    buffer,
                                                    &offset,
                                                    CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_to_struct(&client_flight->finished,
                                        buffer,
                                        &offset,
                                        CTLS_ENTITY_CLIENT);
}

ctls_status_t ctls_hsmg_client_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_hsmg_client_flight_t const *
                                              client_flight,
                                              ctls_wire_format_t const wire_format) {
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_hsmg_certificate_to_wire(buffer,
                                           offset,
                                           &client_flight->certificate,
                                           wire_format);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_hsmg_certificate_verify_to_wire(buffer,
                                                  offset,
                                                  &client_flight->certificate_verify);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_hsmg_finished_to_wire(buffer, offset, &client_flight->finished);
}


ctls_status_t ctls_hsmg_alert_create(ctls_hsmg_alert_t *alert,
                                     ctls_hsmg_alert_type_t const description,
                                     ctls_hsmg_alert_level_t const alert_level) {
    CTLS_CHECK_NULL_STRUCT(alert);

    alert->level = alert_level;
    alert->description = description;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_hsmg_alert_to_struct(ctls_hsmg_alert_t *alert,
                                        uint8_t const *buffer,
                                        ctls_size_t *offset) {
    CTLS_CHECK_NULL_STRUCT(alert);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);

    ctls_status_t result = CTLS_STATUS_SUCCESS;
    uint8_t level_u8 = 0;
    uint8_t description_u8 = 0;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &level_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    alert->level = level_u8;

    result = ctls_read_u8(buffer, offset, CTLS_SIZE_WIRE_BUFFER, &description_u8);
    if (result != CTLS_STATUS_SUCCESS) return result;
    alert->description = description_u8;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_hsmg_alert_to_wire(uint8_t *buffer,
                                      ctls_size_t *offset,
                                      ctls_hsmg_alert_t const *alert) {
    CTLS_CHECK_NULL_STRUCT(alert);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_BUFFER(buffer);

    ctls_status_t result = ctls_write_u8(buffer, offset, alert->level, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    result = ctls_write_u8(buffer, offset, alert->description, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;
    return CTLS_STATUS_SUCCESS;
}
