//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//

/**
 * @file ctls.h
 * @brief Top-level cTLS API: connection context, handshake, and application data.
 *
 * This is the main entry point for cTLS. Callers:
 *   1. Populate a ctls_transport_t with send/receive callbacks.
 *   2. Call ctls_context_init() to set up the connection.
 *   3. Call ctls_connect() (client) or ctls_accept() (server) to handshake.
 *   4. Exchange application data with ctls_read() / ctls_write().
 *
 * The context is a singleton: one connection per build target. All subsystems
 * (crypto, record, hshk_data) are reached through the global accessors below
 * rather than through passed pointers, to minimize constrained-target overhead.
 *
 * Error handling: all functions return ctls_status_t. Non-zero means failure;
 * error codes are defined in types.h, range-partitioned by subsystem.
 */

#ifndef CTLS_H
#define CTLS_H

#include <stdbool.h>
#include <stdint.h>
#include "crypto.h"
#include "record.h"

/* ------------------------------------------------------------------ */
/*  MACROS                                                            */
/* ------------------------------------------------------------------ */

/** Return CTLS_STATUS_NULL_PTR if pointer is NULL. */
#define CTLS_CHECK_NULL(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_PTR; } while (0)

/** Return CTLS_STATUS_NULL_BUFFER if the buffer pointer is NULL. */
#define CTLS_CHECK_NULL_BUFFER(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_BUFFER; } while (0)

/** Return CTLS_STATUS_NULL_OFFSET if the offset pointer is NULL. */
#define CTLS_CHECK_NULL_OFFSET(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_OFFSET; } while (0)

/** Return CTLS_STATUS_NULL_STRUCT if the struct pointer is NULL. */
#define CTLS_CHECK_NULL_STRUCT(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_STRUCT; } while (0)

/**
 * Return CTLS_STATUS_BOUNDS_EXCEEDED if writing size bytes starting at
 * offset would exceed limit.
 */
#define CTLS_CHECK_BOUNDS(offset, size, limit) \
    do { if ((offset) + (size) > (limit)) return CTLS_STATUS_BOUNDS_EXCEEDED; } while (0)

/* ------------------------------------------------------------------ */
/*  DEFINITIONS                                                       */
/* ------------------------------------------------------------------ */

/** Scratch wire buffer used during serialization; reused between handshake steps. */
struct ctls_hshk_buffer {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_length;
};

/**
 * Session ticket received in a NewSessionTicket message (RFC 8446 §4.6.1).
 * Stored in hshk_data for potential PSK resumption; not used in the
 * current PSK-less profile.
 */
struct ctls_ticket {
    uint32_t ticket_lifetime;
    uint32_t ticket_age_add;
    uint8_t ticket_nonce[CTLS_SIZE_TICKET_NONCE];
    uint8_t ticket[CTLS_SIZE_TICKET];
    uint16_t ticket_length;
    ctls_extn_new_session_ticket_t extensions;
};

/**
 * Per-connection handshake scratch: randoms, transcript hash, signatures,
 * verify_data, and session ticket. Lives inside ctls_context_t.
 * Keys (finished_key, write keys, IVs) live in ctls_crypto_t, not here.
 */
struct ctls_hshk_data {
    ctls_hshk_state_t state;
    uint16_t sequence_number;
    uint64_t epoch;
    uint8_t transcript_hash[CTLS_SIZE_TRANSCRIPT_HASH]; // running hash snapshot
    uint8_t client_random[CTLS_SIZE_RANDOM];
    uint8_t server_random[CTLS_SIZE_RANDOM];
    uint8_t certificate_request_context[CTLS_SIZE_CERTIFICATE_REQUEST_CONTEXT];
    uint8_t client_signature[CTLS_SIZE_SIGNED_BYTES]; // CertificateVerify signature bytes
    uint8_t server_signature[CTLS_SIZE_SIGNED_BYTES];
    uint8_t client_verify_data[CTLS_SIZE_HASH]; // Finished HMAC output
    uint8_t server_verify_data[CTLS_SIZE_HASH];
    ctls_size_t client_verify_data_length; // actual bytes written by psa_mac_compute
    ctls_size_t server_verify_data_length;
    ctls_ticket_t ticket;
    // flags
    bool isCertificateStatusRequested;
    bool isSignedCertificateTimestampRequested;
};

/** Transport abstraction: pluggable send/receive callbacks over any byte stream. */
struct ctls_transport {
    ctls_recd_send recd_send;
    ctls_recd_receive recd_receive;
};

/** Top-level connection object. Passed into every public API call. */
struct ctls_context {
    ctls_template_t const *template;
    ctls_crypto_t crypto;
    ctls_hshk_buffer_t *hshk_buffer;
    ctls_hshk_data_t hshk_data;
    ctls_transport_t transport;
    ctls_record_t record;
};

/**
 * @brief Global accessors — return pointers into the singleton ctls_context.
 *
 * The context is a module-level static in ctls.c. These accessors let all
 * subsystems read or mutate it without passing the context pointer everywhere.
 * Callers must not free or replace the returned pointers.
 *
 * @return Pointer into the singleton context; never NULL after ctls_context_init().
 */
ctls_template_t const *ctls_template_get(void);
ctls_hshk_data_t *ctls_hshk_data_get(void);
ctls_crypto_t *ctls_crypto_get(void);
ctls_hshk_buffer_t *ctls_hshk_buffer_get(void);
ctls_transport_t *ctls_transport_get(void);
ctls_record_t *ctls_record_get(void);

/**
 * @brief Initialize the connection context and underlying crypto layer.
 *
 * Stores the template (resolved from config.h profile id), copies the
 * transport callbacks, zeroes hshk_data, and calls ctls_crypto_init()
 * (psa_crypto_init, transcript hash start, algorithm/family selection).
 * Must be called before ctls_connect() or ctls_accept().
 *
 * @param context    Caller-allocated context to initialize; must not be NULL.
 * @param transport  Send/receive callback pair; must not be NULL.
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_* code on init failure.
 */
ctls_status_t ctls_context_init(ctls_context_t *context,
                                ctls_transport_t const *transport);

/**
 * @brief Advance the handshake state machine to a new state.
 *
 * Validates that the transition from the current state at *location to state
 * is legal, then writes state into *location. The handshake driver calls this
 * after each message is sent or received to prevent out-of-order processing.
 *
 * @param location  Pointer to the current state variable to update.
 * @param state     Target state to transition to.
 * @return CTLS_STATUS_SUCCESS on a valid transition, CTLS_STATUS_HSHK_INVALID_STATE otherwise.
 */
ctls_status_t ctls_handshake_state_update(ctls_hshk_state_t *location,
                                          ctls_hshk_state_t state);

/**
 * @brief Zero a wire buffer and reset its offset to 0.
 *
 * Used between handshake steps to reclaim the scratch buffer before the
 * next serialization. Does not free memory.
 *
 * @param buffer        Buffer to clear; must be CTLS_SIZE_WIRE_BUFFER bytes.
 * @param buffer_offest Pointer to the offset to reset to 0.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_NULL_BUFFER / CTLS_STATUS_NULL_OFFSET.
 */
ctls_status_t ctls_wire_buffer_clear(uint8_t *buffer, ctls_size_t *buffer_offest);

/**
 * @brief Verify the active template has all mandatory fields set.
 *
 * Checks that cipher_suite, dhe_group, and signature_algorithm are not
 * CTLS_DEFAULT_SENTINEL. Returns an error immediately on the first unset
 * field; callers rely on this before starting the handshake.
 *
 * @return CTLS_STATUS_SUCCESS if all mandatory fields are present,
 *         or CTLS_STATUS_TMPL_INVALID_* on the first missing field.
 */
ctls_status_t ctls_validate_template();

/**
 * @brief Run the full client-side cTLS handshake to completion.
 *
 * Drives the TLS 1.3 state machine (CH → SH → key schedule →
 * server flight → client flight) until CTLS_HSHK_STATE_CONNECTED.
 * Blocks on transport I/O (ctls_transport_t callbacks).
 *
 * @param context  Initialized connection context; must not be NULL.
 * @return CTLS_STATUS_SUCCESS on successful handshake completion,
 *         or the first error returned by any handshake step.
 */
ctls_status_t ctls_connect(ctls_context_t *context);

/**
 * @brief Run the full server-side cTLS handshake to completion.
 *
 * Mirror of ctls_connect() for the server role (CH receive → SH send →
 * key schedule → server flight send → client flight receive).
 *
 * @param context  Initialized connection context; must not be NULL.
 * @return CTLS_STATUS_SUCCESS on successful handshake completion,
 *         or the first error returned by any handshake step.
 */
ctls_status_t ctls_accept(ctls_context_t *context);

/**
 * @brief Receive and decrypt one application data record.
 *
 * Reads from the transport, strips the unified header, and AEAD-decrypts the
 * body into application_data. The caller must supply a buffer of at least
 * application_data_length bytes. Consumes one sequence number on success.
 *
 * @param buffer                Wire buffer (CTLS_SIZE_WIRE_BUFFER bytes) for the raw record.
 * @param application_data      Output buffer for the decrypted plaintext.
 * @param application_data_length  Size of application_data in bytes.
 * @param entity                CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects read key).
 * @return CTLS_STATUS_SUCCESS on success, CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED on tag mismatch,
 *         or CTLS_STATUS_TRANSPORT_RECV_FAILED on I/O error.
 */
ctls_status_t ctls_read(uint8_t *buffer,
                        uint8_t *application_data,
                        ctls_size_t application_data_length,
                        ctls_entity_t entity);

/**
 * @brief Encrypt and send one application data record.
 *
 * AEAD-encrypts application_data, prepends the unified header (which doubles
 * as the AEAD AAD), and writes the result to the transport. Consumes one
 * sequence number on success.
 *
 * @param application_data        Plaintext to encrypt and send.
 * @param application_data_length Number of plaintext bytes.
 * @param entity                  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects write key).
 * @return CTLS_STATUS_SUCCESS on success, CTLS_STATUS_CRYPTO_AEAD_ENCRYPT_FAILED on cipher failure,
 *         or CTLS_STATUS_TRANSPORT_SEND_FAILED on I/O error.
 */
ctls_status_t ctls_write(uint8_t const *application_data,
                         ctls_size_t application_data_length,
                         ctls_entity_t entity);

/**
 * @brief Map a ctls_status_t to its RFC 8446 §6.2 alert type and level.
 *
 * Direct 1:1 mapping for the CTLS_STATUS_ALERT_* band (types.h,
 * 0x0226-0x0240) returned by hooks; every other status is mapped to the
 * closest alert by failure category (record layer, crypto, extensions,
 * ...), defaulting to internal_error. alert_level is FATAL except for
 * close_notify and user_canceled, which are WARNING.
 *
 * @param status      Status code to map (hook return value or any error).
 * @param alert_type  Output: RFC 8446 §6.2 alert description.
 * @param alert_level Output: CTLS_HSMG_ALERT_LEVEL_FATAL or _WARNING.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_INVALID_ARG if status was
 *         CTLS_STATUS_SUCCESS (there is no alert for "no error").
 */
ctls_status_t ctls_status_to_alert_type_map(ctls_status_t status,
                                            ctls_hsmg_alert_type_t *alert_type,
                                            ctls_hsmg_alert_level_t *alert_level);

/**
 * @brief Map status to an alert, send it, and return status unchanged.
 *
 * Single call site for sending alerts (bug 4 fix) — called once from a
 * handshake driver's onerror path. See the definition in ctls.c for the
 * full contract.
 *
 * @param record  Scratch record, cleared and reused to build the alert.
 * @param status  Original failure status to map and report back.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects write key/IV).
 * @param phase   Handshake phase (selects plaintext vs encrypted framing).
 * @return status on success (alert sent), or the first error encountered
 *         while mapping/building/sending the alert.
 */
ctls_status_t ctls_alert_send(ctls_record_t *record,
                              ctls_status_t status,
                              ctls_entity_t entity,
                              ctls_phase_t phase);
#endif
