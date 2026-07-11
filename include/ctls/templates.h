//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//

/**
 * @file templates.h
 * @brief The cTLS template: in-memory profile shared by both peers.
 *
 * draft-ietf-tls-ctls compresses TLS 1.3 by "aggressive use of defaults":
 * both peers hold the same template, identified by a profile id, that
 * predefines protocol parameters. Anything the template pins is never sent —
 * the receiver fills it in from its own copy. The fields of ctls_template_t
 * mirror the template keys of the cTLS draft:
 *
 *   profile_id          selects the template (cTLS "profile")
 *   protocol_version    pinned TLS version (0x0304 = TLS 1.3)
 *   cipher_suite        pinned cipher suite — no negotiation
 *   dhe_group           pinned named group + fixed key share length, so the
 *                       key_share extension sheds group and length fields
 *   signature_algorithm pinned SignatureScheme + fixed signature length
 *   random              length of the Hello random (cTLS allows shortening
 *                       the 32-byte TLS 1.3 random)
 *   mutual_auth         1 = client certificate required
 *   handshake_framing   handshake message framing variant
 *   *_extension         per-message extension blocks (see below)
 *   known_certificates  certificate dictionary: end-entity certs known in
 *                       advance travel as a 1-byte id, not as DER
 *   finished_size       length of the (possibly truncated) Finished MAC
 */

#ifndef CTLS_TEMPLATES_H
#define CTLS_TEMPLATES_H

#include "config.h"
#include "extensions.h"

/** True when a template byte blob is present (non-null, non-empty). */
#define CTLS_IS_TEMPLATE_BYTES_INITIALIZED(buffer, length)          \
    ((buffer) != NULL && length != 0)


/**
 * Raw extension_data bytes stored in the template — no extension_type and
 * no length prefix; serializers add framing when reconstructing TLS 1.3
 * form (see extensions.h).
 */
struct ctls_template_bytes {
    uint8_t *data;
    ctls_size_t length;
};

/**
 * Pinned key exchange: NamedGroup (RFC 8446 §4.2.7) plus the fixed length
 * of its key share. With both pinned, the wire carries bare key bytes.
 */
struct ctls_tmpl_dhe_group {
    ctls_size_t key_share_length;
    ctls_dhe_group_t dhe_group;
};

/**
 * Pinned signature: SignatureScheme (RFC 8446 §4.2.3) plus the fixed
 * signature length, so CertificateVerify needs no length field.
 */
struct ctls_tmpl_signature_algorithm {
    ctls_size_t signature_length;
    ctls_signature_scheme_t signature_algorithm_type;
};

/**
 * Extension values the template predefines for one handshake message.
 * Predefined = exists on the connection but never sent on the wire.
 * Blob-like extensions store raw extension_data (ctls_template_bytes_t);
 * single-value extensions store the bare scalar. A null blob / sentinel
 * scalar means "extension absent for this profile" — see
 * ctls_extn_is_initialized().
 */
struct ctls_tmpl_predefined_extensions {
    ctls_template_bytes_t server_name;
    ctls_max_fragment_length_t maximum_fragment_length;
    ctls_template_bytes_t certificate_status_request;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_template_bytes_t alpn;
    ctls_template_bytes_t signed_certificate_timestamp;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_psk_key_exchange_mode_t psk_key_exchange_modes;
    ctls_template_bytes_t certificate_authorities;
    ctls_extn_post_handshake_auth_t post_handshake_auth;
    ctls_signature_scheme_t signature_algorithm_cert;
};

/**
 * Extension block for one handshake message type:
 *
 *   predefined_extensions      values pinned by the template (not sent)
 *   expected_extensions        extension types that MUST appear dynamically
 *                              on the wire (e.g. 0x0033 key_share)
 *   self_delimiting_extensions extension types sent without a length prefix
 *                              because their content self-delimits
 *   allow_additional           whether extensions beyond the template's
 *                              lists are tolerated
 */
struct ctls_tmpl_extension {
    ctls_tmpl_predefined_extensions_t predefined_extensions;
    ctls_tmpl_expected_extensions_t expected_extensions;
    ctls_tmpl_self_delimiting_extensions_t self_delimiting_aextensions;
    uint16_t allow_additional;
};

/**
 * One entry of the certificate dictionary: peers that already hold each
 * other's certificates exchange the 1-byte certificate_id instead of the
 * full DER blob.
 */
struct ctls_tmpl_known_certificate {
    uint8_t certificate_id;
    uint8_t const *certificate;
    uint16_t certificate_length;
};

struct ctls_tmpl_known_certificates {
    ctls_tmpl_known_certificate_t entries[CTLS_COUNT_KNOWN_CERTIFICATES];
};

/** The template itself — see the file header for per-field semantics. */
struct ctls_template {
    uint32_t profile_id;
    uint16_t ctls_version;
    ctls_protocol_version_t protocol_version;
    ctls_cipher_suite_t cipher_suite;
    ctls_tmpl_dhe_group_t dhe_group;
    ctls_tmpl_signature_algorithm_t signature_algorithm;
    uint16_t random;
    uint8_t mutual_auth;
    uint8_t handshake_framing;
    ctls_tmpl_extension_t client_hello_extension;
    ctls_tmpl_extension_t server_hello_extension;
    ctls_tmpl_extension_t encrypted_extension;
    ctls_tmpl_extension_t certificate_request_extension;
    ctls_tmpl_known_certificates_t known_certificates;
    uint8_t finished_size;
};


/**
 * Load the active profile from context->template_path (set by
 * ctls_template_path_set, called from ctls_context_init before this) and
 * parse it via ctls_template_from_json into context->template.
 *
 * @return CTLS_STATUS_SUCCESS, CTLS_STATUS_TMPL_PATH_NULL (template_path
 *         was never set), CTLS_STATUS_TMPL_JSON_FILE_NOT_FOUND (the file
 *         doesn't exist / can't be opened), or any status
 *         ctls_template_from_json can return.
 */
ctls_status_t ctls_template_set(ctls_context_t *context);

/**
 * Parse a profile JSON document (profile-registry.md's "Profile Table"
 * schema) into a template struct, via jsmn (include/jsmn.h, vendored,
 * zero-alloc — CTLS_SIZE_JSON_TOKENS in config.h bounds the token array).
 * Mandatory fields: profile, version, random, cipherSuite,
 * signatureAlgorithm, dhGroup — CTLS_STATUS_TMPL_JSON_FIELD_MISSING if
 * absent. Optional and left untouched if absent: ctlsVersion, each of
 * clientHelloExtensions/serverHelloExtensions/encryptedExtensions's
 * expectedExtensions/allowAdditional, and knownCertificates (a JSON object
 * keyed by bare-hex certificate_id, e.g. "01" -> hex-encoded DER; not an
 * array — the key already carries the id). Not parsed at all — the JSON
 * schema doesn't model them: mutual_auth, handshake_framing,
 * finished_size, certificate_request_extension, and every
 * predefined_extensions field.
 *
 * @param json         Buffer holding the JSON document.
 * @param json_length  Length of json in bytes.
 * @param tmpl         Output; only the fields above are written — caller
 *                      should zero the struct first (ctls_template_set
 *                      does).
 * @return CTLS_STATUS_SUCCESS, CTLS_STATUS_TMPL_JSON_PARSE_FAILED,
 *         CTLS_STATUS_TMPL_JSON_TOO_MANY_TOKENS, CTLS_STATUS_TMPL_JSON_MALFORMED,
 *         CTLS_STATUS_TMPL_JSON_FIELD_MISSING, CTLS_STATUS_TMPL_JSON_FIELD_INVALID,
 *         or CTLS_STATUS_TMPL_JSON_UNKNOWN_ENUM_NAME.
 */
ctls_status_t ctls_template_from_json(uint8_t const *json,
                                      ctls_size_t json_length,
                                      ctls_template_t *tmpl);

/**
 * Serialize one template element as TLV:
 * element_type(u16) | element_length(u32) | element value.
 * See templates.c for the per-element value layouts.
 */
ctls_status_t ctls_template_element_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_template_t const *template,
                                            ctls_tmpl_type_t type);

/** Serialize one per-message extension block (layout in templates.c). */
ctls_status_t ctls_tmpl_extension_to_wire(uint8_t *buffer,
                                          ctls_size_t *offset,
                                          ctls_hsmg_type_t type,
                                          ctls_tmpl_extension_t const *extensions);

/**
 * Serialize the active template:
 * content_type(u8) | body_length(u24, backfilled) | ctls_version(u8)
 * | element_length(u32, backfilled) | elements.
 * Gives the template a canonical byte form (e.g. for hashing /
 * identification — both peers must derive identical bytes).
 *
 * @param buffer        Output buffer.
 * @param limit         Capacity of buffer; every internal write is bounds-checked
 *                       against this.
 * @param bytes_written Output: total bytes written to buffer.
 */
ctls_status_t ctls_template_to_wire(uint8_t *buffer,
                                    ctls_size_t limit,
                                    ctls_size_t *bytes_written);


#if CTLS_SERVER
// TODO
// Define default profiles for server
#endif

#endif
