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
 * draft-ietf-tls-ctls §2.2 splits the S bit / sequence number field in two,
 * selected at compile time by CTLS_STREAM / _UNRELIABLE
 * (config.h):
 *
 *   CTLS_DATAGRAM (default, UDP-like, "Datagram cTLS"): S bit
 *   keeps its DTLS 1.3 meaning (1-byte vs 2-byte encoding) and the sequence
 *   number is always sent.
 *
 *       config octet (1)   fixed prefix | C | S | L | EE
 *       sequence number    1 byte (S=0) or 2 bytes (S=1)
 *       length             2 bytes when L=1, absent when L=0
 *
 *   CTLS_STREAM (TCP-like, "Stream cTLS"): S bit MUST be
 *   cleared and the sequence number field is omitted entirely — ordering
 *   is the transport's job, not the record layer's.
 *
 *       config octet (1)   fixed prefix | C | S=0 | L | EE
 *       length             2 bytes when L=1, absent when L=0
 *
 *   1..4 bytes total; connection id (C) unsupported. The 2 EE bits carry
 *   the low bits of the 64-bit epoch; the receiver reconstructs the full
 *   value (ctls_epoch_expand) from its own current epoch.
 *
 * # Counters
 *
 * Single sequence space: every record, created or received, consumes one
 * sequence number — peers stay in lockstep (CH=0, SH=1, server flight=2,
 * client flight=3) — regardless of whether the number travels on the wire.
 * Epoch counts key changes (RFC 9147 §6.1: 0 plaintext, 2 handshake keys),
 * bumped by the key schedule, not per message.
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
    ctls_recd_content_type_t content_type; // Used only in CH, SH
    uint32_t profile_id; // Used only in CH, SH; 4 bytes on the wire in CH only (see record.c)
    ctls_record_type_t type; // For internal reference
    ctls_unified_header_t unified_header;
    union {
        ctls_handshake_message_t handshake;
        ctls_application_data_t application;
        ctls_hsmg_alert_t alert;
    } record_body;
};

/*
 * Record counters over hshk_data (single sequence space: every record
 * created or received consumes one sequence number; epoch counts key
 * changes). Increment hooks live in ctls_record_serialize /
 * ctls_record_deserialize; the epoch is bumped by the key schedule.
 */
/** Increment hshk_data->sequence_number; called once per record sent or received. */
ctls_status_t ctls_sequence_number_counter_increment(void);
/** Copy current hshk_data->sequence_number into *sequence_number. */
ctls_status_t ctls_sequence_number_counter_get(uint16_t *sequence_number);
/** Reset hshk_data->sequence_number to 0. */
ctls_status_t ctls_sequence_number_counter_reset(void);

/** Increment hshk_data->epoch; called by the key schedule on each key change. */
ctls_status_t ctls_epoch_counter_increment(void);
/** Copy current hshk_data->epoch into *epoch. */
ctls_status_t ctls_epoch_counter_get(uint64_t *epoch);
/** Reset hshk_data->epoch to 0. */
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
 * Back-fill the length field in unified_header after body serialization;
 * recomputes l_bit (set when length >= 1) and aad_length accordingly.
 * Call before ctls_record_encrypt so the header bytes used as AAD are final.
 */
ctls_status_t ctls_unified_header_length_update(ctls_unified_header_t *unified_header,
                                                uint16_t length);

/**
 * Wire preprocess: bytes -> record type/content_type, decrypting if needed.
 * Called once from ctls_record_deserialize before any per-message parsing.
 *
 * Config-octet bits 001 (0xE0 mask == 0x20) select the ENCRYPTED path:
 * deserializes the unified header, validates aad_length != 0, epoch low
 * bits match hshk_data->epoch, and sequence_number matches
 * hshk_data->sequence_number (out-of-order/replay detection), backfills
 * length from bytes_received when the header omitted it (l_bit == 0), then
 * decrypts the body into plaintext and reads content_type from the
 * decrypted byte. Otherwise treated as PLAINTEXT and content_type is read
 * directly from buffer[0]. Either way content_type is validated against
 * the known ctls_recd_content_type_t values before returning.
 *
 * @param buffer           Raw wire bytes received from the transport.
 * @param bytes_received   Total bytes in buffer (used to back-fill header length).
 * @param record           Output: type and content_type are set; unified_header
 *                         is filled for the ENCRYPTED path.
 * @param plaintext        Output buffer for the decrypted body (ENCRYPTED path only).
 * @param plaintext_offset Output: bytes written to plaintext (ENCRYPTED path only).
 * @return CTLS_STATUS_SUCCESS, CTLS_STATUS_RECD_INVALID_AAD_LENGTH,
 *         CTLS_STATUS_RECD_EPOCH_MISMATCH, CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH,
 *         CTLS_STATUS_RECD_INVALID_CONTENT_TYPE, or a decrypt error from
 *         ctls_record_decrypt.
 */
ctls_status_t ctls_record_preprocess(uint8_t const *buffer,
                                     ctls_size_t bytes_received,
                                     ctls_record_t *record,
                                     uint8_t *plaintext,
                                     ctls_size_t *plaintext_offset);


/**
 * Record struct -> final wire bytes. PLAINTEXT records serialize directly;
 * ENCRYPTED records serialize body into a scratch buffer and go through
 * ctls_record_encrypt. On success consumes one sequence number.
 */
ctls_status_t ctls_record_serialize(ctls_record_t *record,
                                    ctls_hsmg_type_t hsmg_type,
                                    uint8_t *buffer,
                                    ctls_size_t *offset,
                                    ctls_entity_t entity);
/**
 * Received wire bytes -> record struct, dispatched by expected message
 * type (decryption happens inside the per-message to_struct). On success
 * consumes one sequence number to stay in lockstep with the peer.
 */
ctls_status_t ctls_record_deserialize(ctls_record_t *record,
                                      ctls_hsmg_type_t hsmg_type,
                                      uint8_t const *buffer,
                                      ctls_size_t bytes_received);

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

/**
 * Build a ClientHello record struct: content_type = 0x16, profile_id from
 * the active template, record type PLAINTEXT, body via
 * ctls_hsmg_client_hello_create.
 */
ctls_status_t ctls_recd_client_hello_create(ctls_record_t *record);
/**
 * Parse a compact ClientHello record from buffer+*offset: reads content_type,
 * profile_id, then dispatches to ctls_hsmg_client_hello_to_struct.
 */
ctls_status_t ctls_recd_client_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset);
/** Emit a compact ClientHello record: content_type, profile_id, then the handshake body. */
ctls_status_t ctls_recd_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t wire_format);

/** Build a ServerHello record struct: generate server random, fill extensions, set framing fields. */
ctls_status_t ctls_recd_server_hello_create(ctls_record_t *record);
/** Parse a compact ServerHello record from buffer+*offset (mirrors ctls_recd_client_hello_to_struct). */
ctls_status_t ctls_recd_server_hello_to_struct(ctls_record_t *record,
                                               uint8_t const *buffer,
                                               ctls_size_t *offset);
/** Emit a compact ServerHello record: content_type, record_body_length, then the handshake body — no profile_id (only ClientHello carries it). */
ctls_status_t ctls_recd_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_record_t const *record,
                                             ctls_wire_format_t wire_format);

/**
 * Build the server's combined flight record: ENCRYPTED record carrying
 * EncryptedExtensions + Certificate + CertificateVerify + Finished.
 * Unified header filled with ctls_unified_header_build; body via
 * ctls_hsmg_server_flight_create.
 */
ctls_status_t ctls_recd_server_flight_create(ctls_record_t *record);
/**
 * Parse the server flight from raw wire bytes: deserialize unified header,
 * decrypt AEAD body, then ctls_hsmg_server_flight_to_struct on plaintext.
 * buffer must point at the first byte of the unified header.
 */
ctls_status_t ctls_recd_server_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer);
/**
 * Emit the server flight. TRANSCRIPT_HASH: each sub-message (EE, Cert,
 * CertVerify, Finished) written in TLS 1.3 form and fed to the transcript
 * hash. DEFAULT: ctls_record_serialize encrypts the whole flight body as
 * one AEAD record. entity selects write key / IV.
 */
ctls_status_t ctls_recd_server_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_record_t *record,
                                              ctls_wire_format_t wire_format,
                                              ctls_entity_t entity);

/**
 * Build the client's combined flight record: ENCRYPTED record carrying
 * Certificate + CertificateVerify + Finished.
 * Unified header filled with ctls_unified_header_build; body via
 * ctls_hsmg_client_flight_create.
 */
ctls_status_t ctls_recd_client_flight_create(ctls_record_t *record);
/**
 * Parse the client flight: decrypt AEAD body then
 * ctls_hsmg_client_flight_to_struct on plaintext.
 * buffer must point at the first byte of the unified header.
 */
ctls_status_t ctls_recd_client_flight_to_struct(ctls_record_t *record,
                                                uint8_t const *buffer);
/**
 * Emit the client flight. Mirror of ctls_recd_server_flight_to_wire for
 * Certificate/CertificateVerify/Finished. entity selects write key / IV.
 */
ctls_status_t ctls_recd_client_flight_to_wire(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_record_t *record,
                                              ctls_wire_format_t wire_format,
                                              ctls_entity_t entity);

/**
 * Receive an encrypted application data record: AEAD-decrypt from buffer
 * into application_data (caller-allocated, application_data_length bytes).
 * entity selects the read key / IV. On success consumes one sequence number.
 */
ctls_status_t ctls_recd_application_data_deserialize(uint8_t const *buffer,
                                                     uint8_t *application_data,
                                                     ctls_size_t application_data_length,
                                                     ctls_entity_t entity);
/**
 * Send an application data record: AEAD-encrypt application_data into
 * buffer with unified header prepended. *offset advances past the whole
 * record. entity selects the write key / IV. On success consumes one
 * sequence number.
 */
ctls_status_t ctls_recd_application_data_serialize(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   uint8_t const *application_data,
                                                   ctls_size_t application_data_length,
                                                   ctls_entity_t entity);

/**
 * Build an Alert record: clears record, sets content_type = alert, builds
 * the unified header (length 0 — filled in later by to_wire), then the
 * 2-byte Alert body via ctls_hsmg_alert_create.
 */
ctls_status_t ctls_recd_alert_create(ctls_record_t *record,
                                     ctls_hsmg_alert_type_t description,
                                     ctls_hsmg_alert_level_t alert_level);
/**
 * Parse a received Alert: PLAINTEXT records read the 2-byte body directly;
 * ENCRYPTED records go through ctls_record_decrypt first. Dispatched on
 * record->type, set earlier by ctls_record_preprocess.
 */
ctls_status_t ctls_recd_alert_to_struct(ctls_record_t *record, uint8_t const *buffer);
/**
 * Emit an Alert record. PLAINTEXT writes the 2-byte body straight to
 * buffer; ENCRYPTED writes it to a scratch plaintext buffer first, then
 * AEAD-encrypts via ctls_record_encrypt (entity/phase select the write
 * key/IV and plaintext vs handshake framing).
 */
ctls_status_t ctls_recd_alert_to_wire(uint8_t *buffer,
                                      ctls_size_t *offset,
                                      ctls_record_t *record,
                                      ctls_entity_t entity,
                                      ctls_phase_t phase);

#endif
