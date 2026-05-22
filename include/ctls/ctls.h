//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#ifndef CTLS__H
#define CTLS__H

#include <stdint.h>
#include "crypto.h"
#include "record.h"

/* ------------------------------------------------------------------ */
/*  MACROS                                                            */
/* ------------------------------------------------------------------ */

#define CTLS_CHECK_NULL(pointer)                                    \
    do {                                                            \
        if ((pointer) == NULL)                                      \
            return (ctls_op_status_t) {                             \
                        .source = CTLS_ERROR_SOURCE_INTERNAL,       \
                        .code = CTLS_OP_STATUS_FAIL,                \
                        .external_code = CTLS_OP_STATUS_FAIL,       \
                    };                                              \
    } while (0)

#define CTLS_CHECK_BOUNDS(offset, size, limit)                      \
    do {                                                            \
        if ((offset) + (size) > (limit))                            \
            return (ctls_op_status_t) {                             \
                        .source = CTLS_ERROR_SOURCE_INTERNAL,       \
                        .code = CTLS_OP_STATUS_OVERFLOW,            \
                        .external_code = CTLS_OP_STATUS_OVERFLOW,   \
                    };                                              \
    } while (0)

/* ------------------------------------------------------------------ */
/*  DEFINITIONS                                                       */
/* ------------------------------------------------------------------ */

struct ctls_hshk_buffer {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_length;
};

struct ctls_hshk_data {
    uint8_t transcript_hash[CTLS_SIZE_TRANSCRIPT_HASH];
    uint8_t client_random[CTLS_SIZE_RANDOM];
    uint8_t client_public_ephemeral_key[CTLS_DEFAULT_SIGNATURE_LENGTH];
    uint8_t server_random[CTLS_SIZE_RANDOM];
    uint8_t server_public_ephemeral_key[CTLS_DEFAULT_SIGNATURE_LENGTH];
    uint8_t shared_ephemeral_secret[CTLS_SIZE_KEY_SHARE];
    uint8_t early_secret[CTLS_SIZE_HASH];
    uint8_t derived_secret[CTLS_SIZE_HASH];
    uint8_t handshake_secret[CTLS_SIZE_HASH];
    uint8_t client_handshake_traffic_secret[CTLS_SIZE_HASH];
    uint8_t client_handshake_key[CTLS_SIZE_AEAD_KEY];
    uint8_t client_handshake_iv_key[CTLS_SIZE_IV];
    uint8_t server_handshake_traffic_secret[CTLS_SIZE_HASH];
    uint8_t server_handshake_key[CTLS_SIZE_AEAD_KEY];
    uint8_t server_handshake_iv_key[CTLS_SIZE_IV];
    uint8_t certificate_request_context[CTLS_SIZE_CERTIFICATE_REQUEST_CONTEXT];
};

struct ctls_op_status {
    ctls_op_status_code_t code;
    ctls_error_source_t source;
    uint16_t external_code;
};

struct ctls_transport {
    ctls_recd_send recd_send;
    ctls_recd_receive recd_receive;
};

struct ctls_context {
    ctls_template_t const *template;
    ctls_crypto_t crypto;
    ctls_hshk_state_t state;
    ctls_hshk_buffer_t *hshk_buffer;
    ctls_hshk_data_t hshk_data;
    ctls_transport_t transport;
    uint64_t sequence_number;
    ctls_record_t record;
};

ctls_template_t const *ctls_template_get(void);
ctls_hshk_data_t *ctls_hshk_data_get(void);
ctls_crypto_t *ctls_crypto_get(void);
ctls_hshk_buffer_t *ctls_hshk_buffer_get(void);

ctls_op_status_t ctls_context_init(ctls_context_t *context,
                                   ctls_transport_t const *transport);
ctls_op_status_t ctls_handshake_state_update(ctls_hshk_state_t *location,
                                             ctls_hshk_state_t state);
void ctls_wire_buffer_clear(uint8_t *buffer);
ctls_op_status_t ctls_recd_buffer_clear(ctls_record_t *record_buffer);
ctls_op_status_t ctls_validate_template();
ctls_op_status_t ctls_connect(ctls_context_t *context);
ctls_op_status_t ctls_read(ctls_context_t const *context,
                           uint8_t *buffer,
                           size_t buffer_length);
ctls_op_status_t ctls_write(ctls_context_t const *context,
                            uint8_t *buffer,
                            size_t buffer_length);


#endif
