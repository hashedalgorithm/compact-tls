//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#ifndef CTLS_H
#define CTLS_H

#include <stdbool.h>
#include <stdint.h>
#include "crypto.h"
#include "record.h"

/* ------------------------------------------------------------------ */
/*  MACROS                                                            */
/* ------------------------------------------------------------------ */

#define CTLS_CHECK_NULL(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_PTR; } while (0)

#define CTLS_CHECK_NULL_BUFFER(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_BUFFER; } while (0)

#define CTLS_CHECK_NULL_OFFSET(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_OFFSET; } while (0)

#define CTLS_CHECK_NULL_STRUCT(pointer) \
    do { if ((pointer) == NULL) return CTLS_STATUS_NULL_STRUCT; } while (0)

#define CTLS_CHECK_BOUNDS(offset, size, limit) \
    do { if ((offset) + (size) > (limit)) return CTLS_STATUS_BOUNDS_EXCEEDED; } while (0)

/* ------------------------------------------------------------------ */
/*  DEFINITIONS                                                       */
/* ------------------------------------------------------------------ */

struct ctls_hshk_buffer {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_length;
};

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
    bool isHandshakeComplete;
    bool isCertificateStatusRequested;
    bool isSignedCertificateTimestampRequested;
};


struct ctls_transport {
    ctls_recd_send recd_send;
    ctls_recd_receive recd_receive;
};

/** Top-level connection object. Passed into every public API call. */
struct ctls_context {
    ctls_template_t const *template;
    ctls_crypto_t crypto;
    ctls_hshk_state_t state;
    ctls_hshk_buffer_t *hshk_buffer;
    ctls_hshk_data_t hshk_data;
    ctls_transport_t transport;
    ctls_record_t record;
};

/** Global accessors — return pointers into the singleton ctls_context. */
ctls_template_t const *ctls_template_get(void);
ctls_hshk_data_t *ctls_hshk_data_get(void);
ctls_crypto_t *ctls_crypto_get(void);
ctls_hshk_buffer_t *ctls_hshk_buffer_get(void);
ctls_transport_t *ctls_transport_get(void);
ctls_record_t *ctls_record_get(void);

/** Initialize context with transport callbacks and run ctls_crypto_init. */
ctls_status_t ctls_context_init(ctls_context_t *context,
                                ctls_transport_t const *transport);
/** Advance the handshake state machine; returns error if transition is invalid. */
ctls_status_t ctls_handshake_state_update(ctls_hshk_state_t *location,
                                          ctls_hshk_state_t state);
/** Zero buffer and reset offset to 0. */
ctls_status_t ctls_wire_buffer_clear(uint8_t *buffer, ctls_size_t *buffer_offest);
/** Verify the template has a cipher suite, DHE group, and signature algorithm set. */
ctls_status_t ctls_validate_template();
/** Run the full client-side TLS 1.3 handshake to completion. */
ctls_status_t ctls_connect(ctls_context_t *context);
/** Read decrypted application data into buffer. */
ctls_status_t ctls_read(uint8_t *buffer,
                        uint8_t const *application_data,
                        ctls_size_t application_data_length);
/** Encrypt and send application data from buffer. */
ctls_status_t ctls_write(uint8_t const *application_data,
                         ctls_size_t application_data_length);
#endif
