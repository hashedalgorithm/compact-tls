//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

/**
 * @file record.h
 * @brief cTLS record layer: unified header, record protection, counters.
 *
 * References:
 *   - RFC 8446 §5 — TLS 1.3 record protection (AEAD, per-record nonce)
 *   - RFC 9147 §4 — DTLS 1.3 unified header (this layer borrows its model:
 *     config octet with flag bits, 2-bit epoch, variable-size fields)
 *   - draft-ietf-tls-ctls — compact framing, template compression
 *
 * # Record forms
 *
 * Two record types (ctls_record_type_t):
 *
 *   PLAINTEXT — ClientHello / ServerHello only. No unified header; framed
 *               by content_type + profile_id (CH) per cTLS.
 *   ENCRYPTED — everything after the key schedule. Framing:
 *
 *       unified header (clear, = AEAD AAD) | AES-GCM(body) | tag(16)
 *
 * # Unified header wire format (RFC 9147 §4 model)
 *
 *       config octet (1)   fixed prefix | C | S | L | EE
 *       sequence number    1 byte (S=0) or 2 bytes (S=1)
 *       length             2 bytes when L=1, absent when L=0
 *
 *   2..5 bytes total; connection id (C) unsupported. The 2 EE bits carry
 *   the low bits of the 64-bit epoch; the receiver reconstructs the full
 *   value (ctls_epoch_expand) from its own current epoch.
 *
 * # Counters
 *
 * Single sequence space: every record, created or received, consumes one
 * sequence number — peers stay in lockstep (CH=0, SH=1, server flight=2,
 * client flight=3). Epoch counts key changes (RFC 9147 §6.1: 0 plaintext,
 * 2 handshake keys), bumped by the key schedule, not per message.
 *
 * # Naming
 *
 *   ctls_record_*    generic layer: serialize/deserialize dispatch,
 *                    encrypt/decrypt
 *   ctls_recd_<msg>_create     build record struct (sender)
 *   ctls_recd_<msg>_to_struct  parse received bytes into record struct
 *   ctls_recd_<msg>_to_wire    emit bytes; wire_format selects compact
 *                    cTLS bytes (DEFAULT) or reconstructed TLS 1.3 bytes
 *                    for the transcript hash (TRANSCRIPT_HASH) — see
 *                    extensions.h for the full wire-format design
 */

#ifndef CTLS_RECORD_H
#define CTLS_RECORD_H

#include "hsmg.h"

/** Decoded view of the config octet (first header byte). */
struct ctls_recd_config_octet {
    uint8_t c_bit; // connection_id
    uint8_t s_bit; // sequence_number
    uint8_t l_bit; // length
    uint8_t epoch;
};

/**
 * Unified header (RFC 9147 §4 model) — encrypted records only; CH/SH are
 * framed differently. Serialized form doubles as the AEAD AAD.
 */
struct ctls_unified_header {
    /* Except for Client Hello and Server Hello */
    ctls_recd_config_octet_t config_octet;
    // To implement later when there is a scenario where UDP source address change
    // uint8_t connection_id;
    uint16_t sequence_number;
    uint16_t length;
    /* Except for Client Hello and Server Hello */
    uint64_t epoch;
    /* For internal purposes */
    ctls_size_t aad_length;
};

struct ctls_application_data {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t length;
};

/** One record: framing fields + the handshake message body it carries. */
struct ctls_record {
    uint8_t content_type; // Used only in CH, SH
    uint8_t profile_id; // Used only in CH, SH
    ctls_record_type_t type; // For internal reference
    ctls_unified_header_t unified_header;
    union {
        ctls_handshake_message_t handshake;
        ctls_application_data_t application;
    } record_body;
};

/*
 * Record counters over hshk_data (single sequence space: every record
 * created or received consumes one sequence number; epoch counts key
 * changes). Increment hooks live in ctls_record_serialize /
 * ctls_record_deserialize; the epoch is bumped by the key schedule.
 */
ctls_status_t ctls_sequence_number_counter_increment(void);
ctls_status_t ctls_sequence_number_counter_get(uint16_t *sequence_number);
ctls_status_t ctls_sequence_number_counter_reset(void);

ctls_status_t ctls_epoch_counter_increment(void);
ctls_status_t ctls_epoch_counter_get(uint64_t *epoch);
ctls_status_t ctls_epoch_counter_reset(void);

/** Computes serialized header (= AAD) size into unified_header->aad_length. */
ctls_status_t ctls_aad_length_calculate(ctls_unified_header_t *unified_header);

/**
 * Fill a header from current hshk_data state: sequence number, epoch (full
 * + compressed 2 bits), s_bit from counter range, l_bit from length.
 * length is usually 0 at create time — final value known only after body
 * serialization.
 */
ctls_status_t ctls_unified_header_build(ctls_unified_header_t *unified_header,
                                        uint16_t length);
/** Header struct -> 2..5 wire bytes (layout in file header above). */
ctls_status_t ctls_unified_header_serialize(ctls_unified_header_t const *unified_header,
                                            uint8_t *buffer,
                                            ctls_size_t *offset);
/**
 * Wire bytes -> header struct. Expands the 2 epoch bits against the value
 * already in unified_header->epoch (caller seeds it with the current
 * epoch). Also computes aad_length.
 */
ctls_status_t ctls_unified_header_deserialize(ctls_unified_header_t *unified_header,
                                              uint8_t const *buffer,
                                              ctls_size_t *offset);

/**
 * Record struct -> final wire bytes. PLAINTEXT records serialize directly;
 * ENCRYPTED records serialize body into a scratch buffer and go through
 * ctls_record_encrypt. On success consumes one sequence number.
 */
ctls_status_t ctls_record_serialize(ctls_record_t const *record,
                                    uint8_t *buffer,
                                    ctls_size_t *offset);
/**
 * Received wire bytes -> record struct, dispatched by expected message
 * type (decryption happens inside the per-message to_struct). On success
 * consumes one sequence number to stay in lockstep with the peer.
 */
ctls_status_t ctls_record_deserialize(ctls_record_t *record,
                                      ctls_hsmg_type_t hsmg_type,
                                      uint8_t const *buffer);

/**
 * Encrypted record -> body plaintext. Deserializes the header (its wire
 * bytes are the AAD — the AEAD tag check authenticates it), decrypts the
 * body, then syncs the authenticated epoch back into hshk_data.
 */
ctls_status_t ctls_record_decrypt(ctls_record_t *record,
                                  uint8_t const *buffer,
                                  uint8_t *plaintext,
                                  ctls_size_t *plaintext_bytes_written,
                                  ctls_phase_t phase,
                                  ctls_entity_t entity);
/**
 * Body plaintext -> encrypted record. Serializes the header into buffer
 * (clear, as AAD) and AEAD-encrypts plaintext right after it:
 *
 *     unified header | AES-GCM(plaintext) | tag(16)
 */
ctls_status_t ctls_record_encrypt(uint8_t *buffer,
                                  ctls_size_t *offset,
                                  ctls_unified_header_t const *unified_header,
                                  uint8_t const *plaintext,
                                  ctls_size_t plaintext_length,
                                  ctls_size_t *ciphertext_length,
                                  ctls_phase_t phase,
                                  ctls_entity_t entity);

/** Zero the whole record struct (also used between handshake steps). */
ctls_status_t ctls_recd_buffer_clear(ctls_record_t *record_buffer);

/* ------------------------------------------------------------------ */
/* Per-message record functions. Byte layouts live in record.c; the    */
/* create/to_struct/to_wire convention is described in the file header.*/
/* ------------------------------------------------------------------ */

ctls_status_t ctls_recd_client_hello_create(ctls_record_t *record);
ctls_status_t ctls_recd_client_hello_to_struct();
ctls_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_server_hello_create(void);
ctls_status_t ctls_recd_server_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset);
ctls_status_t ctls_recd_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_encrypted_extensions_create(void);
ctls_status_t ctls_recd_encrypted_extensions_to_struct(ctls_record_t *record,
                                                       uint8_t const *buffer);
ctls_status_t ctls_recd_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_record_t const *record,
                                                     ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_certificate_request_create(void);
ctls_status_t ctls_recd_certificate_request_to_struct(ctls_record_t *record,
                                                      uint8_t const *buffer);
ctls_status_t ctls_recd_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_record_t const *record,
                                                    ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_certificate_create(ctls_record_t *record, ctls_entity_t entity);
ctls_status_t ctls_recd_certificate_to_struct(ctls_record_t *record,
                                              uint8_t const *buffer);
ctls_status_t ctls_recd_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_record_t const *record,
                                            ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_certificate_verify_create(ctls_record_t *record,
                                                  ctls_entity_t entity);
ctls_status_t ctls_recd_certificate_verify_to_struct(ctls_record_t *record,
                                                     uint8_t const *buffer,
                                                     ctls_entity_t entity);
ctls_status_t ctls_recd_certificate_verify_to_wire(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_record_t const *record,
                                                   ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_finished_create(ctls_record_t *record, ctls_entity_t entity);
ctls_status_t ctls_recd_finished_to_struct(ctls_record_t *record,
                                           uint8_t const *buffer,
                                           ctls_entity_t entity);
ctls_status_t ctls_recd_finished_to_wire(uint8_t *buffer,
                                         ctls_size_t *offset,
                                         ctls_record_t const *record,
                                         ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_server_flight_create(ctls_record_t *record);
ctls_status_t ctls_recd_server_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer);
ctls_status_t ctls_recd_server_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_record_t const *record,
                                              ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_client_flight_create(ctls_record_t *record);
ctls_status_t ctls_recd_client_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer);
/**
 * Combined flight emit: header -> buffer (clear, AAD position), message
 * bodies -> plaintext scratch, then ctls_record_encrypt writes the final
 * encrypted record into buffer.
 */
ctls_status_t ctls_recd_client_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              uint8_t *plaintext,
                                              ctls_size_t *plaintext_bytes_written,
                                              ctls_record_t const *record,
                                              ctls_wire_format_t wire_format);

ctls_status_t ctls_recd_application_data_deserialize(uint8_t const *buffer,
                                                     uint8_t *application_data,
                                                     ctls_size_t application_data_length,
                                                     ctls_entity_t entity);
ctls_status_t ctls_recd_application_data_serialize(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   uint8_t const *application_data,
                                                   ctls_size_t application_data_length,
                                                   ctls_entity_t entity);
#endif
