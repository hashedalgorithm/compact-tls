//
// Created by SanjayKumar Kumaravelan on 16/04/26.
//

#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#include "ctls/extensions.h"
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
ctls_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg) {
    ctls_template_t const *template = ctls_template_get();
    ctls_crypto_t const *crypto = ctls_crypto_get();
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(template);
    CTLS_CHECK_NULL(crypto);
    CTLS_CHECK_NULL(hshk_data);

    ctls_status_t const result = ctls_random_generate(hshk_data->client_random,
                                                      &hsmg->handshake_message_body.
                                                      client_hello.random.buffer_length,
                                                      template->random);
    hsmg->handshake_message_body.client_hello.random.buffer = hshk_data->client_random;

    if (result != CTLS_STATUS_SUCCESS) return result;

    hsmg->handshake_message_body.client_hello.cipher_suite = template->cipher_suite;
    hsmg->handshake_message_body.client_hello.protocol_version = template->
            protocol_version;
    hsmg->handshake_message_body.client_hello.legacy_session_id = 0x00;
    hsmg->handshake_message_body.client_hello.legacy_compression_methods = 0x00;

    return ctls_extn_client_hello_create(&hsmg->handshake_message_body.client_hello.
                                         extensions);
}


ctls_status_t ctls_hsmg_client_hello_to_struct() {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Emit ClientHello.
 *
 * DEFAULT (compact cTLS):
 *
 *     body_length(u16, backfilled)
 *     | message_type(u8) | sequence_number(u16)
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
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
        offset += 2;

        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u16(buffer, offset, hsmg->sequence_number);

        ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer);

        if (template->cipher_suite == 0) {
            ctls_write_u16(buffer,
                           offset,
                           sizeof(hsmg->handshake_message_body.client_hello.
                               cipher_suite));
            ctls_write_u16(buffer, offset, CTLS_DEFAULT_SENTINEL);
        }

        ctls_status_t const result = ctls_extn_client_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.client_hello.extensions,
            CTLS_WIRE_FORMAT_DEFAULT);

        ctls_write_u16(buffer, &body_start, *offset - body_start);

        return result;
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_size_t hsmg_body_length_offset = *offset;
        *offset += 3;

        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2);
        ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.client_hello.random.buffer_length,
                         hsmg->handshake_message_body.client_hello.random.buffer);
        ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.client_hello.
                          legacy_session_id));
        ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.client_hello.legacy_session_id);
        ctls_write_u16(buffer,
                       offset,
                       sizeof(hsmg->handshake_message_body.client_hello.cipher_suite));
        ctls_write_u16(buffer,
                       offset,
                       hsmg->handshake_message_body.client_hello.cipher_suite);
        ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.client_hello.
                          legacy_compression_methods));
        ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.client_hello.
                      legacy_compression_methods);

        ctls_status_t const result = ctls_extn_client_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.client_hello.extensions,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u24(buffer,
                       &hsmg_body_length_offset,
                       *offset - hsmg_body_length_offset);

        return CTLS_STATUS_SUCCESS;
    }
    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_server_hello_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Parse a compact ServerHello:
 *
 *     message_type(u8)
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

    hsmg->message_type = ctls_read_u8(buffer, offset);

    ctls_read_bytes(hshk_data->server_random, template->random, buffer, offset);
    hsmg->handshake_message_body.server_hello.random.buffer = hshk_data->server_random;
    hsmg->handshake_message_body.server_hello.random.buffer_length = template->random;

    hsmg->handshake_message_body.server_hello.cipher_suite =
            ctls_read_u16(buffer, offset);

    hsmg->handshake_message_body.server_hello.protocol_version = template->
            protocol_version;
    hsmg->handshake_message_body.server_hello.legacy_compression_method = 0;
    hsmg->handshake_message_body.server_hello.legacy_session_id_echo = 0;

    offset += 2;
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

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_size_t hsmg_body_length_offset = *offset;
        *offset += 3;

        ctls_write_u16(buffer, offset, CTLS_HSMG_PROTOCOL_VERSION_1_2);
        ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.server_hello.random.buffer_length,
                         hsmg->handshake_message_body.server_hello.random.buffer);
        ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.server_hello.
                          legacy_session_id_echo));
        ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.server_hello.legacy_session_id_echo);
        ctls_write_u16(buffer,
                       offset,
                       hsmg->handshake_message_body.server_hello.cipher_suite);
        ctls_write_u8(buffer,
                      offset,
                      sizeof(hsmg->handshake_message_body.server_hello.
                          legacy_compression_method));
        ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.server_hello.
                      legacy_compression_method);

        ctls_status_t const result = ctls_extn_server_hello_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.server_hello.extensions,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u24(buffer,
                       &hsmg_body_length_offset,
                       *offset - hsmg_body_length_offset);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_encrypted_extensions_create(void) {
    return CTLS_STATUS_NOT_IMPLEMENTED;
}

/*
 * Parse EncryptedExtensions (RFC 8446 §4.3.1). Wire carries only
 * message_type(u8); the whole extension set is template-predefined and
 * reconstructed locally.
 */
ctls_status_t ctls_hsmg_encrypted_extensions_to_struct(ctls_handshake_message_t *hsmg,
                                                       uint8_t const *buffer) {
    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL_BUFFER(buffer);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);

    return ctls_extn_encrypted_extensions_to_struct(&hsmg->handshake_message_body.
                                                    encrypted_extensions.extensions);
}

/*
 * Emit EncryptedExtensions, TRANSCRIPT_HASH only (RFC 8446 §4.3.1:
 * "Extension extensions<0..2^16-1>;"):
 *
 *     extensions_length(u16, backfilled) | extensions in TLS 1.3 framing
 */
ctls_status_t ctls_hsmg_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_handshake_message_t const *hsmg,
                                                     ctls_wire_format_t const
                                                     wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(hsmg);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_size_t extensions_length_offset = *offset;

        ctls_status_t const result = ctls_extn_encrypted_extensions_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.encrypted_extensions.extensions,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer,
                       &extensions_length_offset,
                       *offset - extensions_length_offset);
        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

ctls_status_t ctls_hsmg_certificate_request_create(void) {
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
ctls_status_t ctls_hsmg_certificate_request_to_struct(ctls_handshake_message_t *hsmg,
                                                      uint8_t const *buffer) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(hshk_data);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);

    ctls_size_t const certificate_request_context_length = ctls_read_u8(buffer, &offset);
    if (certificate_request_context_length > 0) {
        ctls_read_bytes(hshk_data->certificate_request_context,
                        certificate_request_context_length,
                        buffer,
                        &offset);
    }

    return ctls_extn_certificate_request_to_struct(&hsmg->handshake_message_body.
                                                   certificate_request.extensions);
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
                                                    ctls_handshake_message_t const *hsmg,
                                                    ctls_wire_format_t const
                                                    wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(hsmg);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.certificate_request.
                      certificate_request_context.buffer_length);

        if (hsmg->handshake_message_body.certificate_request.certificate_request_context.
            buffer_length > 0) {
            ctls_write_bytes(buffer,
                             offset,
                             hsmg->handshake_message_body.certificate_request.
                             certificate_request_context.buffer_length,
                             hsmg->handshake_message_body.certificate_request.
                             certificate_request_context.buffer);
        }

        ctls_size_t extensions_length_offset = *offset;
        ctls_status_t const result = ctls_extn_certificate_request_to_wire(buffer,
            offset,
            &hsmg->handshake_message_body.certificate_request.extensions,
            CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
        if (result != CTLS_STATUS_SUCCESS) return result;

        ctls_write_u16(buffer,
                       &extensions_length_offset,
                       *offset - extensions_length_offset);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

/*
 * Build a Certificate message (RFC 8446 §4.4.2) with the cTLS certificate
 * dictionary: a single entry carrying this build's certificate_id
 * (CTLS_ENTITY_CERTIFICATE_ID) instead of DER, echoing the stored
 * certificate_request_context, plus per-entry extensions (OCSP/SCT) the
 * peer requested.
 */
ctls_status_t ctls_hsmg_certificate_create(ctls_handshake_message_t *hsmg,
                                           ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(hshk_data);

    hsmg->handshake_message_body.certificate.certificate_request_context.buffer =
            hshk_data->certificate_request_context;
    hsmg->handshake_message_body.certificate.certificate_request_context.buffer_length =
            CTLS_SIZE_CERTIFICATE_REQUEST_CONTEXT;

    hsmg->handshake_message_body.certificate.certificate_entries[0].certificate_id =
            CTLS_ENTITY_CERTIFICATE_ID;

    return ctls_extn_certificate_create(&hsmg->handshake_message_body.certificate.
                                        certificate_entries[0].extensions,
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
ctls_status_t ctls_hsmg_certificate_to_struct(ctls_handshake_message_t *hsmg,
                                              uint8_t const *buffer) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL(hshk_data);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);

    ctls_size_t const certificate_request_context_length = ctls_read_u8(buffer, &offset);
    if (certificate_request_context_length > 0) {
        ctls_read_bytes(hshk_data->certificate_request_context,
                        certificate_request_context_length,
                        buffer,
                        &offset);
    } else ctls_read_u8(buffer, &offset);

    ctls_size_t const certificate_entries_length = ctls_read_u24(buffer, &offset);
    ctls_size_t certificate_entries_index = 0;
    ctls_size_t const certificate_entries_absolute_length =
            offset + certificate_entries_length;

    while (offset < certificate_entries_absolute_length) {
        offset += 2; // certificate data length
        hsmg->handshake_message_body.certificate.certificate_entries[
            certificate_entries_index].certificate_id = ctls_read_u16(buffer, &offset);

        ctls_size_t const certificate_extensions_length = ctls_read_u24(buffer, &offset);
        if (certificate_extensions_length <= 0) {
            continue;
        }

        ctls_status_t const result =
                ctls_extn_certificate_to_struct(&hsmg->handshake_message_body.certificate.
                                                certificate_entries[
                                                    certificate_entries_index].
                                                extensions);
        if (result != CTLS_STATUS_SUCCESS) return result;

        certificate_entries_index++;
    }

    hsmg->handshake_message_body.certificate.certificate_count =
            certificate_entries_index;

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
                                            ctls_handshake_message_t const *hsmg,
                                            ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL(hsmg);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u8(buffer,
                      offset,
                      hsmg->handshake_message_body.certificate.certificate_request_context
                      .buffer_length);

        if (hsmg->handshake_message_body.certificate.certificate_request_context.
            buffer_length > 0) {
            ctls_write_bytes(buffer,
                             offset,
                             hsmg->handshake_message_body.certificate.
                             certificate_request_context.buffer_length,
                             hsmg->handshake_message_body.certificate.
                             certificate_request_context.buffer);
        }

        ctls_size_t certificates_length_offset = *offset;
        *offset += 2;

        for (uint8_t i = 0; i < hsmg->handshake_message_body.certificate.certificate_count
             ; i++) {
            ctls_write_u16(buffer,
                           offset,
                           sizeof(hsmg->handshake_message_body.certificate.
                               certificate_entries[i].certificate_id));
            ctls_write_u16(buffer,
                           offset,
                           hsmg->handshake_message_body.certificate.certificate_entries[i]
                           .certificate_id);
            ctls_size_t certificate_extensions_length_offset = *offset;
            *offset += 2;
            ctls_status_t const result = ctls_extn_certificate_to_wire(buffer,
                offset,
                &hsmg->handshake_message_body.certificate.certificate_entries[i].
                extensions,
                CTLS_WIRE_FORMAT_TRANSCRIPT_HASH);
            if (result != CTLS_STATUS_SUCCESS) return result;

            ctls_write_u16(buffer,
                           &certificate_extensions_length_offset,
                           *offset - certificate_extensions_length_offset);
        }

        ctls_write_u16(buffer,
                       &certificates_length_offset,
                       *offset - certificates_length_offset);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

/*
 * Build CertificateVerify (RFC 8446 §4.4.3): scheme pinned by the template,
 * signature computed by ctls_signed_bytes_generate over the §4.4.3 signed
 * content (context string + Transcript-Hash). signature aliases hshk_data's
 * signed-bytes storage for this entity.
 */
ctls_status_t ctls_hsmg_certificate_verify_create(ctls_handshake_message_t *hsmg,
                                                  ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();
    ctls_template_t const *template = ctls_template_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL_STRUCT(template);
    CTLS_CHECK_NULL(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_HSMG_INVALID_ENTITY;

    hsmg->handshake_message_body.certificate_verify.signature_scheme = template->
            signature_algorithm.signature_algorithm_type;

    ctls_status_t const result = ctls_signed_bytes_generate(entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    hsmg->handshake_message_body.certificate_verify.signature =
            entity == CTLS_ENTITY_CLIENT
                ? hshk_data->client_signature
                : hshk_data->server_signature;

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
ctls_status_t ctls_hsmg_certificate_verify_to_struct(ctls_handshake_message_t *hsmg,
                                                     uint8_t const *buffer,
                                                     ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(hshk_data);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);
    hsmg->handshake_message_body.certificate_verify.signature_scheme =
            ctls_read_u16(buffer, &offset);

    ctls_size_t const signed_bytes_length = ctls_read_u16(buffer, &offset);
    ctls_read_bytes(entity == CTLS_ENTITY_CLIENT
                        ? hshk_data->client_signature
                        : hshk_data->server_signature,
                    signed_bytes_length,
                    buffer,
                    &offset);

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
                                                   ctls_handshake_message_t const *hsmg,
                                                   ctls_wire_format_t const wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(hsmg);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_u16(buffer,
                       offset,
                       hsmg->handshake_message_body.certificate_verify.signature_scheme);
        ctls_write_u16(buffer,
                       offset,
                       hsmg->handshake_message_body.certificate_verify.signature_length);
        ctls_write_bytes(buffer,
                         offset,
                         hsmg->handshake_message_body.certificate_verify.signature_length,
                         hsmg->handshake_message_body.certificate_verify.signature);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}

/*
 * Build Finished (RFC 8446 §4.4.4): derive this entity's finished key, then
 * verify_data = HMAC(finished_key, Transcript-Hash(...)). verify_data
 * aliases hshk_data storage.
 */
ctls_status_t ctls_hsmg_finished_create(ctls_handshake_message_t *hsmg,
                                        ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL(hshk_data);

    if (entity != CTLS_ENTITY_CLIENT && entity != CTLS_ENTITY_SERVER)
        return CTLS_STATUS_HSMG_INVALID_ENTITY;

    ctls_status_t result = ctls_finished_key_generate(entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_verify_data_generate(entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    hsmg->handshake_message_body.finished.verify_data = entity == CTLS_ENTITY_CLIENT
                                                            ? hshk_data->
                                                            client_verify_data
                                                            : hshk_data->
                                                            server_verify_data;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Parse Finished: message_type(u8) | verify_data[CTLS_SIZE_HASH]. Fixed
 * size, no length field — RFC 8446 §4.4.4:
 * "opaque verify_data[Hash.length];"
 */
ctls_status_t ctls_hsmg_finished_to_struct(ctls_handshake_message_t *hsmg,
                                           uint8_t const *buffer,
                                           ctls_entity_t const entity) {
    ctls_hshk_data_t *hshk_data = ctls_hshk_data_get();

    CTLS_CHECK_NULL_STRUCT(hsmg);
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(hshk_data);

    ctls_size_t offset = 0;

    hsmg->message_type = ctls_read_u8(buffer, &offset);

    ctls_read_bytes(entity == CTLS_ENTITY_CLIENT
                        ? hshk_data->client_verify_data
                        : hshk_data->server_verify_data,
                    CTLS_SIZE_HASH,
                    buffer,
                    &offset);
    hsmg->handshake_message_body.finished.verify_data = entity == CTLS_ENTITY_CLIENT
                                                            ? hshk_data->
                                                            client_verify_data
                                                            : hshk_data->
                                                            server_verify_data;

    return CTLS_STATUS_SUCCESS;
}

/*
 * Emit Finished, TRANSCRIPT_HASH only:
 *
 *     msg_type(u8) | verify_data[CTLS_SIZE_HASH]
 */
ctls_status_t ctls_hsmg_finished_to_wire(uint8_t *buffer,
                                         ctls_size_t *offset,
                                         ctls_handshake_message_t const *hsmg,
                                         ctls_wire_format_t wire_format) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(offset);
    CTLS_CHECK_NULL_STRUCT(hsmg);

    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
        ctls_write_u8(buffer, offset, hsmg->message_type);
        ctls_write_bytes(buffer,
                         offset,
                         CTLS_SIZE_HASH,
                         hsmg->handshake_message_body.finished.verify_data);

        return CTLS_STATUS_SUCCESS;
    }

    return CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT;
}
