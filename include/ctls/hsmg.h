//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

/**
 * @file hsmg.h
 * @brief Handshake message layer: TLS 1.3 message bodies, cTLS-compressed.
 *
 * Sits between the record layer (record.h) and the extension layer
 * (extensions.h). Structs here mirror the handshake message bodies of
 * RFC 8446, Section 4:
 *
 *     struct {
 *         HandshakeType msg_type;    // u8
 *         uint24 length;
 *         select (Handshake.msg_type) { ... };
 *     } Handshake;
 *
 * with the cTLS compressions applied on the wire: legacy fields dropped,
 * template-pinned values omitted, certificates replaced by dictionary ids.
 *
 * Wire formats (same convention as extensions.h):
 *
 *     CTLS_WIRE_FORMAT_DEFAULT          compact cTLS bytes, sent on wire
 *     CTLS_WIRE_FORMAT_TRANSCRIPT_HASH  reconstructed TLS 1.3 Handshake
 *                                       bytes, fed to the transcript hash
 *                                       so the key schedule matches a
 *                                       TLS 1.3 run (never sent)
 *
 * Naming: *_create builds the struct from template/handshake state (sender),
 * *_to_struct parses received bytes (+ template reconstruction), *_to_wire
 * emits bytes in the chosen format. Byte layouts are documented in hsmg.c.
 *
 * client_flight / server_flight are cTLS combined messages: the whole
 * encrypted flight (EE/Certificate/CertificateVerify/Finished) packed into
 * one record instead of one record per message.
 */

#ifndef CTLS_HSMG_H
#define CTLS_HSMG_H

#include "extensions.h"


/**
 * ClientHello, RFC 8446 §4.1.2:
 *
 *     struct {
 *         ProtocolVersion legacy_version = 0x0303;
 *         Random random;
 *         opaque legacy_session_id<0..32>;
 *         CipherSuite cipher_suites<2..2^16-2>;
 *         opaque legacy_compression_methods<1..2^8-1>;
 *         Extension extensions<8..2^16-1>;
 *     } ClientHello;
 *
 * cipher_suites collapses to the one suite the template pins; the legacy
 * fields exist only for transcript reconstruction (always 0 in cTLS).
 */
struct ctls_hsmg_client_hello {
    ctls_protocol_version_t protocol_version;
    ctls_hshk_buffer_block_t random;
    uint8_t legacy_session_id;
    ctls_cipher_suite_t cipher_suite;
    uint8_t legacy_compression_methods;
    ctls_extn_client_hello_t extensions;
};

/** ServerHello, RFC 8446 §4.1.3 — same shape as ClientHello, one suite. */
struct ctls_hsmg_server_hello {
    ctls_protocol_version_t protocol_version;
    ctls_hshk_buffer_block_t random;
    uint8_t legacy_session_id_echo;
    ctls_cipher_suite_t cipher_suite;
    uint8_t legacy_compression_method;
    ctls_extn_server_hello_t extensions;
};

/** EncryptedExtensions, RFC 8446 §4.3.1: just an extension list. */
struct ctls_hsmg_encrypted_extensions {
    ctls_extn_encrypted_extensions_t extensions;
};

/**
 * CertificateRequest, RFC 8446 §4.3.2:
 * certificate_request_context<0..2^8-1> + extensions.
 */
struct ctls_hsmg_certificate_request {
    ctls_hshk_buffer_block_t certificate_request_context;
    ctls_extn_certificate_request_t extensions;
};

/**
 * CertificateEntry, RFC 8446 §4.4.2 — with the cTLS certificate dictionary
 * applied: cert_data<1..2^24-1> is replaced by the certificate_id from the
 * template's known_certificates; the DER never travels.
 */
struct ctls_hsmg_certificate_entry {
    uint16_t certificate_id;
    ctls_extn_certificate_t extensions;
};

/** Certificate message, RFC 8446 §4.4.2: context + certificate_list. */
struct ctls_hsmg_certificate {
    ctls_hshk_buffer_block_t certificate_request_context;
    ctls_hsmg_certificate_entry_t certificate_entries[CTLS_COUNT_CERTIFICATE_ENTRY];
    uint8_t certificate_count;
};

/**
 * CertificateVerify, RFC 8446 §4.4.3:
 *
 *     struct {
 *         SignatureScheme algorithm;
 *         opaque signature<0..2^16-1>;
 *     } CertificateVerify;
 *
 * signature points into hshk_data's signed-bytes storage.
 */
struct ctls_hsmg_certificate_verify {
    ctls_signature_scheme_t signature_scheme;
    uint8_t *signature;
    uint8_t signature_length;
};

/**
 * Finished, RFC 8446 §4.4.4: "opaque verify_data[Hash.length];" — fixed
 * size (CTLS_SIZE_HASH), no length field. Points into hshk_data.
 */
struct ctls_hsmg_finished {
    uint8_t *verify_data;
};

struct ctls_hsmg_application_data {
    uint8_t *payload;
    ctls_size_t payload_length;
};

/** Alert, RFC 8446 §6: level(u8) + description(u8). */
struct ctls_hsmg_alert {
    uint8_t level;
    uint8_t description;
};

/**
 * cTLS combined message: the client's second flight
 * (Certificate, CertificateVerify, Finished — RFC 8446 §4.4) in one record.
 */
struct ctls_hsmg_client_flight {
    ctls_hsmg_certificate_t certificate;
    ctls_hsmg_certificate_verify_t certificate_verify;
    ctls_hsmg_finished_t finished;
};

/**
 * cTLS combined message: the server's flight after ServerHello
 * (EncryptedExtensions, Certificate, CertificateVerify, Finished) in one
 * record.
 */
struct ctls_hsmg_server_flight {
    ctls_hsmg_encrypted_extensions_t encrypted_extensions;
    ctls_hsmg_certificate_t certificate;
    ctls_hsmg_certificate_verify_t certificate_verify;
    ctls_hsmg_finished_t finished;
};

struct ctls_new_session_ticket {
    ctls_ticket_t *ticket;
};

/** Body union — discriminated by ctls_handshake_message.message_type. */
typedef union {
    ctls_hsmg_client_hello_t client_hello;
    ctls_hsmg_server_hello_t server_hello;
    ctls_hsmg_encrypted_extensions_t encrypted_extensions;
    ctls_hsmg_certificate_request_t certificate_request;
    ctls_hsmg_certificate_t certificate;
    ctls_hsmg_certificate_verify_t certificate_verify;
    ctls_hsmg_finished_t finished;
    ctls_hsmg_application_data_t application_data;
    ctls_hsmg_alert_t alert;
    ctls_hsmg_client_flight_t client_flight;
    ctls_hsmg_server_flight_t server_flight;
} ctls_hsmg_body_t;

/**
 * One handshake message (or combined flight). sequence_number is the cTLS
 * handshake-level sequence carried in the compact ClientHello.
 */
struct ctls_handshake_message {
    uint16_t sequence_number;
    ctls_hsmg_body_t handshake_message_body;
};


/**
 * Fill a ClientHello from the template: fresh random of template->random
 * bytes, pinned version/suite, legacy fields zeroed, extensions via
 * ctls_extn_client_hello_create (generates the ephemeral key share).
 */
ctls_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg);
ctls_status_t ctls_hsmg_client_hello_to_struct(void);
/** Emit ClientHello — compact cTLS or TLS 1.3 transcript form (see hsmg.c). */
ctls_status_t ctls_hsmg_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_handshake_message_t const *hsmg,
                                             ctls_wire_format_t wire_format);

ctls_status_t ctls_hsmg_server_hello_create(void);
/**
 * Parse a compact ServerHello: random, cipher suite and key share from the
 * wire; everything the template pins (version, legacy fields) reconstructed.
 */
ctls_status_t ctls_hsmg_server_hello_to_struct(ctls_handshake_message_t *hsmg,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset);
/** Emit ServerHello (TLS 1.3 transcript reconstruction only). */
ctls_status_t ctls_hsmg_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_handshake_message_t const *hsmg,
                                             ctls_wire_format_t wire_format);

ctls_status_t ctls_hsmg_encrypted_extensions_create(void);
/**
 * Parse EncryptedExtensions: only the message type is on the wire; the
 * extension content is reconstructed from the template.
 */
ctls_status_t ctls_hsmg_encrypted_extensions_to_struct(ctls_handshake_message_t *hsmg,
                                                       uint8_t const *buffer);
/** Emit EncryptedExtensions (TLS 1.3 transcript reconstruction only). */
ctls_status_t ctls_hsmg_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_handshake_message_t const *hsmg,
                                                     ctls_wire_format_t wire_format);

ctls_status_t ctls_hsmg_certificate_request_create(void);
/**
 * Parse CertificateRequest: message type + certificate_request_context from
 * the wire (context saved to hshk_data for the client's Certificate reply,
 * RFC 8446 §4.4.2); extensions from the template.
 */
ctls_status_t ctls_hsmg_certificate_request_to_struct(ctls_handshake_message_t *hsmg,
                                                      uint8_t const *buffer);
/** Emit CertificateRequest (TLS 1.3 transcript reconstruction only). */
ctls_status_t ctls_hsmg_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_handshake_message_t const *hsmg,
                                                    ctls_wire_format_t wire_format);

/**
 * Fill a Certificate message: one entry carrying this build's own
 * certificate id (CTLS_ENTITY_CERTIFICATE_ID) plus per-entry extensions the
 * peer requested (OCSP status / SCT).
 */
ctls_status_t ctls_hsmg_certificate_create(ctls_handshake_message_t *hsmg,
                                           ctls_entity_t entity);
/** Parse a Certificate message (dictionary ids, layout in hsmg.c). */
ctls_status_t ctls_hsmg_certificate_to_struct(ctls_handshake_message_t *hsmg,
                                              uint8_t const *buffer);
/** Emit Certificate (TLS 1.3 transcript reconstruction, dictionary ids). */
ctls_status_t ctls_hsmg_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_handshake_message_t const *hsmg,
                                            ctls_wire_format_t wire_format);

/**
 * Fill a CertificateVerify: signature scheme from the template, signature
 * computed over the current transcript via ctls_signed_bytes_generate
 * (RFC 8446 §4.4.3 signed content).
 */
ctls_status_t ctls_hsmg_certificate_verify_create(ctls_handshake_message_t *hsmg,
                                                  ctls_entity_t entity);
/** Parse CertificateVerify: scheme(u16) | sig_length(u16) | signature. */
ctls_status_t ctls_hsmg_certificate_verify_to_struct(ctls_handshake_message_t *hsmg,
                                                     uint8_t const *buffer,
                                                     ctls_entity_t entity);
/** Emit CertificateVerify (TLS 1.3 transcript reconstruction only). */
ctls_status_t ctls_hsmg_certificate_verify_to_wire(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_handshake_message_t const *hsmg,
                                                   ctls_wire_format_t wire_format);

/**
 * Fill a Finished: derive the finished key and compute verify_data =
 * HMAC(finished_key, Transcript-Hash) per RFC 8446 §4.4.4.
 */
ctls_status_t ctls_hsmg_finished_create(ctls_handshake_message_t *hsmg,
                                        ctls_entity_t entity);
/** Parse Finished: fixed CTLS_SIZE_HASH verify_data bytes, no length field. */
ctls_status_t ctls_hsmg_finished_to_struct(ctls_handshake_message_t *hsmg,
                                           uint8_t const *buffer,
                                           ctls_entity_t entity);
/** Emit Finished (TLS 1.3 transcript reconstruction only). */
ctls_status_t ctls_hsmg_finished_to_wire(uint8_t *buffer,
                                         ctls_size_t *offset,
                                         ctls_handshake_message_t const *hsmg,
                                         ctls_wire_format_t wire_format);


#endif
