//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#include <string.h>
#include "ctls/ctls.h"
#include "ctls/templates.h"
#include "ctls/core.h"

/* Singleton connection state — set once in ctls_context_init, read via the
 * ctls_*_get() accessors. Using file-scope pointers keeps every subsystem
 * (crypto, record, extension) free of context parameters while still
 * allowing a single context to be swapped in future multi-connection work. */
static ctls_template_t const *g_template;
static ctls_hshk_data_t *g_hshk_data;
static ctls_crypto_t *g_crypto;
static ctls_hshk_buffer_t *g_hshk_buffer;
static ctls_hshk_buffer_t g_hshk_buffer_storage; /* backing storage for hshk_buffer */
static ctls_transport_t *g_transport;
static ctls_record_t *g_record;


ctls_template_t const *ctls_template_get(void) {
    return g_template;
}
ctls_hshk_data_t *ctls_hshk_data_get(void) {
    return g_hshk_data;
}
ctls_crypto_t *ctls_crypto_get(void) {
    return g_crypto;
}
ctls_hshk_buffer_t *ctls_hshk_buffer_get(void) {
    return g_hshk_buffer;
}
ctls_transport_t *ctls_transport_get(void) {
    return g_transport;
}
ctls_record_t *ctls_record_get(void) {
    return g_record;
}


ctls_status_t ctls_handshake_state_update(ctls_hshk_state_t *location,
                                          ctls_hshk_state_t const state) {
    CTLS_CHECK_NULL(location);
    *location = state;
    return CTLS_STATUS_SUCCESS;
}

/*
 * Mandatory-field check (ambiguities.md §1.1's mandatory subset: profile_id,
 * protocol_version, cipher_suite, signature_algorithm, known_certificates —
 * dhe_group checked too, pre-existing). Each must hold a real value, not a
 * zero/sentinel default, or the connection is refused before any bytes go
 * on the wire.
 */
ctls_status_t ctls_validate_template() {
    ctls_template_t const *template = g_template;
    if (!template) return CTLS_STATUS_TMPL_NULL;

    if (template->profile_id == 0) return CTLS_STATUS_TMPL_INVALID_PROFILE_ID;
    if (template->protocol_version != CTLS_HSMG_PROTOCOL_VERSION_1_3)
        return CTLS_STATUS_TMPL_INVALID_PROTOCOL_VERSION;
    if (template->cipher_suite == 0) return CTLS_STATUS_TMPL_INVALID_CIPHER_SUITE;
    if (template->dhe_group.dhe_group == 0) return CTLS_STATUS_TMPL_INVALID_DHE_GROUP;
    if (template->signature_algorithm.signature_algorithm_type == 0)
        return CTLS_STATUS_TMPL_INVALID_SIG_ALGORITHM;

    uint8_t known_certificate_present = 0;
    for (ctls_size_t i = 0; i < CTLS_COUNT_KNOWN_CERTIFICATES; i++) {
        if (template->known_certificates.entries[i].certificate != NULL &&
            template->known_certificates.entries[i].certificate_length != 0) {
            known_certificate_present = 1;
            break;
        }
    }
    if (!known_certificate_present) return CTLS_STATUS_TMPL_INVALID_KNOWN_CERTIFICATES;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_wire_buffer_clear(uint8_t *buffer, ctls_size_t *buffer_offest) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(buffer_offest);

    memset(buffer, 0, CTLS_SIZE_WIRE_BUFFER);
    *buffer_offest = 0;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_template_path_set(ctls_context_t *context, char const *path) {
    CTLS_CHECK_NULL_STRUCT(context);
    CTLS_CHECK_NULL(path);

    context->template_path = path;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_context_init(ctls_context_t *context,
                                ctls_transport_t const *transport,
                                char const *template_path) {
    CTLS_CHECK_NULL(template_path);

    memset(context, 0, sizeof(ctls_context_t));
    memset(&context->record, 0, sizeof(ctls_record_t));
    memset(&g_hshk_buffer_storage, 0, sizeof(g_hshk_buffer_storage));

    ctls_status_t result = ctls_template_path_set(context, template_path);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_template_set(context);
    if (result != CTLS_STATUS_SUCCESS) return result;

    context->transport = *transport;
    context->hshk_buffer = &g_hshk_buffer_storage;

    g_template = context->template;
    g_hshk_data = &context->hshk_data;
    g_crypto = &context->crypto;
    g_hshk_buffer = context->hshk_buffer;
    g_transport = &context->transport;
    g_record = &context->record;

    result = ctls_crypto_init();
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_core_handshake_state_update(CTLS_HSHK_STATE_START);

    return ctls_validate_template();
}

/*
 * ctls_send / ctls_receive — every transport I/O call in this file goes
 * through these instead of context->transport.recd_send/recd_receive
 * directly, so CTLS_DATAGRAM builds get retransmission-on-timeout
 * (RFC 9147 §5.8.1/§5.8.2) without touching the raw transport callbacks or
 * any caller above this file. CTLS_STREAM has no RFC-mandated timeout
 * (RFC 8446 assumes a reliable transport underneath), so it's a direct
 * passthrough.
 */
ctls_status_t ctls_send(uint8_t *buffer, ctls_size_t const length) {
#if CTLS_DATAGRAM
    ctls_transport_t const *transport = ctls_transport_get();
    ctls_hshk_buffer_t *hshk_buffer = ctls_hshk_buffer_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(transport);
    CTLS_CHECK_NULL_STRUCT(hshk_buffer);
    CTLS_CHECK_BOUNDS(0, length, CTLS_SIZE_WIRE_BUFFER);

    /* Stash a copy for ctls_receive to retransmit on timeout — the
     * caller's buffer may be cleared/reused right after this returns. */
    memcpy(hshk_buffer->buffer, buffer, length);
    hshk_buffer->buffer_length = length;

    return transport->recd_send(buffer, length);
#elif CTLS_STREAM
    ctls_transport_t const *transport = ctls_transport_get();
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_STRUCT(transport);

    return transport->recd_send(buffer, length);

#else
    (void) buffer;
    (void) length;
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

ctls_status_t
ctls_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t const capacity) {
#if CTLS_DATAGRAM
    ctls_transport_t const *transport = ctls_transport_get();
    ctls_hshk_buffer_t *hshk_buffer = ctls_hshk_buffer_get();

    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(length);
    CTLS_CHECK_NULL_STRUCT(transport);
    CTLS_CHECK_NULL_STRUCT(hshk_buffer);

#if !CTLS_DTLS_RETRANSMISSION_ENABLED
    /* Host transport handles loss recovery (e.g. SCHC ACK_ALWAYS) —
     * single blocking receive, fail on timeout. No flight retransmit here. */
    (void) hshk_buffer;
    return transport->recd_receive(buffer, length, capacity,
                                   CTLS_DTLS_RECEIVE_TIMEOUT_MS);
#else
    /* RFC 9147 §5.8: receive with a doubling timer; on each timeout,
     * retransmit the last flight and back off, giving up after
     * CTLS_DTLS_RETRANSMIT_MAX_RETRIES. */
    uint32_t timeout_ms = CTLS_DTLS_RETRANSMIT_TIMEOUT_INITIAL_MS;
    uint32_t retry_count = 0;

    for (;;) {
        ctls_status_t const result =
                transport->recd_receive(buffer, length, capacity, timeout_ms);
        if (result != CTLS_STATUS_TRANSPORT_TIMEOUT) return result;

        /* Give up after CTLS_DTLS_RETRANSMIT_MAX_RETRIES retransmits rather
         * than doubling all the way out to the RFC's 60s timer cap — bounds
         * how long a stuck handshake blocks the caller. */
        if (retry_count >= CTLS_DTLS_RETRANSMIT_MAX_RETRIES)
            return CTLS_STATUS_TRANSPORT_TIMEOUT;
        retry_count++;

        /* §5.8.1: timer expiry -> retransmit the last flight. Nothing to
         * retransmit while waiting for the peer's opening message (nothing
         * sent yet on this side) — just keep waiting with a longer timer. */
        if (hshk_buffer->buffer_length != 0) {
            ctls_status_t const send_result =
                    ctls_send(hshk_buffer->buffer, hshk_buffer->buffer_length);
            if (send_result != CTLS_STATUS_SUCCESS) return send_result;
        }

        /* §5.8.2: double the timer, capped at the max. */
        timeout_ms = (timeout_ms > CTLS_DTLS_RETRANSMIT_TIMEOUT_MAX_MS / 2)
                             ? CTLS_DTLS_RETRANSMIT_TIMEOUT_MAX_MS
                             : timeout_ms * 2;
    }
#endif
#elif CTLS_STREAM
    ctls_transport_t const *transport = ctls_transport_get();
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(length);
    CTLS_CHECK_NULL_STRUCT(transport);

    /* No RFC-mandated timeout — timeout_ms=0 tells the transport callback
     * "no deadline, block as usual." */
    return transport->recd_receive(buffer, length, capacity, 0);
#else
    (void) buffer;
    (void) length;
    (void) capacity;
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}


/*
 * Full client-side TLS 1.3 handshake sequence (RFC 8446 §2):
 *   1. Send ClientHello (plaintext)
 *   2. Receive ServerHello — triggers key schedule
 *   3. Receive server flight (EE + Certificate + CertificateVerify + Finished)
 *      decrypted with handshake keys
 *   4. If mutual_auth: send client flight (Certificate + CertVerify + Finished)
 *   5. Derive application traffic keys
 *
 * On any error the state machine moves to CTLS_HSHK_STATE_ERROR, buffers
 * are cleared, and the error is propagated to the caller.
 */
#if CTLS_CLIENT
ctls_status_t ctls_handshake(ctls_context_t *context) {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;

    // Client Hello
    ctls_status_t result = ctls_recd_client_hello_create(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_serialize(&context->record,
                                   CTLS_HSMG_TYPE_CLIENT_HELLO,
                                   buffer,
                                   &buffer_offset,
                                   CTLS_ENTITY_CLIENT);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_client_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Server Hello
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_receive(buffer, &buffer_offset, sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(
            &context->record, CTLS_HSMG_TYPE_SERVER_HELLO, buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_server_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Key schedule
    result = ctls_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_WAIT_ENCRYPTED_EXTENSIONS);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Server Flight
    result = ctls_receive(buffer, &buffer_offset, sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(
            &context->record, CTLS_HSMG_TYPE_SERVER_FLIGHT, buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_server_flight_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Client Flight
    if (context->template->mutual_auth == 1) {
        result = ctls_recd_client_flight_create(&context->record);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_record_serialize(&context->record,
                                       CTLS_HSMG_TYPE_CLIENT_FLIGHT,
                                       buffer,
                                       &buffer_offset,
                                       CTLS_ENTITY_CLIENT);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_send(buffer, buffer_offset);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_core_client_flight_op(&context->record);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;
    }

    result = ctls_application_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    return ctls_core_handshake_state_update(CTLS_HSHK_STATE_CONNECTED);


onerror:
    ctls_core_handshake_state_update(CTLS_HSHK_STATE_ERROR);

    ctls_recd_buffer_clear(&context->record);
    ctls_wire_buffer_clear(buffer, &buffer_offset);

    return ctls_alert_send(
            &context->record, result, CTLS_ENTITY_CLIENT, CTLS_PHASE_HANDSHAKE);
}
#endif /* CTLS_CLIENT */


/*
 * Full server-side TLS 1.3 handshake sequence (RFC 8446 §2):
 *   1. Receive ClientHello (plaintext) — parse key share
 *   2. Send ServerHello (plaintext) — includes server key share
 *   3. Derive handshake keys from shared ECDH secret
 *   4. Send server flight (EE + Certificate + CertificateVerify + Finished)
 *      encrypted with server handshake write key
 *   5. If mutual_auth: receive client flight (Certificate + CertVerify + Finished)
 *   6. Derive application traffic keys
 *
 * On any error moves to CTLS_HSHK_STATE_ERROR and propagates.
 */
#if CTLS_SERVER
ctls_status_t ctls_server_handshake(ctls_context_t *context) {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;

    // Client Hello
    ctls_status_t result = ctls_receive(buffer, &buffer_offset, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(
            &context->record, CTLS_HSMG_TYPE_CLIENT_HELLO, buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_client_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Server Hello
    result = ctls_recd_buffer_clear(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_recd_server_hello_create(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_serialize(&context->record,
                                   CTLS_HSMG_TYPE_SERVER_HELLO,
                                   buffer,
                                   &buffer_offset,
                                   CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_server_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Key schedule
    result = ctls_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Server Flight
    result = ctls_recd_server_flight_create(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_serialize(&context->record,
                                   CTLS_HSMG_TYPE_SERVER_FLIGHT,
                                   buffer,
                                   &buffer_offset,
                                   CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_server_flight_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Client Flight (mutual auth)
    if (context->template->mutual_auth == 1) {
        result = ctls_wire_buffer_clear(buffer, &buffer_offset);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_receive(buffer, &buffer_offset, sizeof(buffer));
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_record_deserialize(
                &context->record, CTLS_HSMG_TYPE_CLIENT_FLIGHT, buffer, buffer_offset);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_core_client_flight_op(&context->record);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_transcript_hash_update(&context->record,
                                             CTLS_HSMG_TYPE_CLIENT_FLIGHT);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;
    }

    result = ctls_application_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    return ctls_core_handshake_state_update(CTLS_HSHK_STATE_CONNECTED);

onerror:
    ctls_core_handshake_state_update(CTLS_HSHK_STATE_ERROR);

    ctls_recd_buffer_clear(&context->record);
    ctls_wire_buffer_clear(buffer, &buffer_offset);

    return ctls_alert_send(
            &context->record, result, CTLS_ENTITY_SERVER, CTLS_PHASE_HANDSHAKE);
}
#endif /* CTLS_SERVER */


ctls_status_t ctls_connect(ctls_context_t *context) {
    ctls_status_t const result = ctls_validate_template();
    if (result != CTLS_STATUS_SUCCESS) return result;

#if CTLS_CLIENT
    return ctls_handshake(context);
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

ctls_status_t ctls_accept(ctls_context_t *context) {
    ctls_status_t const result = ctls_validate_template();
    if (result != CTLS_STATUS_SUCCESS) return result;

#if CTLS_SERVER
    return ctls_server_handshake(context);
#else
    return CTLS_STATUS_INVALID_INVOCATION;
#endif
}

ctls_status_t ctls_read(uint8_t *buffer,
                        uint8_t *application_data,
                        ctls_size_t *application_data_length,
                        ctls_entity_t const entity) {
    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_OFFSET(application_data_length);

    ctls_size_t buffer_offset = 0;
    ctls_status_t result = ctls_receive(buffer, &buffer_offset, CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    ctls_record_t *record = ctls_record_get();
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_recd_content_type_t content_type = CTLS_RECD_CONTENT_TYPE_INVALID;
    result = ctls_recd_application_data_deserialize(
            buffer, application_data, application_data_length, &content_type, entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    if (content_type == CTLS_RECD_CONTENT_TYPE_ALERT) {
        if (record->record_body.alert.description == CTLS_HSMG_ALERT_TYPE_CLOSE_NOTIFY) {
            result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_CLOSED);
            if (result != CTLS_STATUS_SUCCESS) return result;
            return CTLS_STATUS_ALERT_CLOSE_NOTIFY;
        }
        return CTLS_STATUS_RECD_PEER_ALERT_RECEIVED;
    }

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_write(uint8_t const *application_data,
                         ctls_size_t const application_data_length,
                         ctls_entity_t const entity) {
    ctls_record_t const *record = ctls_record_get();

    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_STRUCT(record);

    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;

    ctls_status_t const result = ctls_recd_application_data_serialize(
            buffer, &buffer_offset, application_data, application_data_length, entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_send(buffer, buffer_offset);
}

ctls_status_t ctls_close(ctls_context_t *context, ctls_entity_t const entity) {
    CTLS_CHECK_NULL_STRUCT(context);

    ctls_status_t const result = ctls_alert_send(
            &context->record, CTLS_STATUS_ALERT_CLOSE_NOTIFY, entity,
            CTLS_PHASE_APPLICATION_DATA);
    if (result != CTLS_STATUS_ALERT_CLOSE_NOTIFY) return result;

    return ctls_core_handshake_state_update(CTLS_HSHK_STATE_CLOSED);
}


ctls_status_t ctls_status_to_alert_type_map(ctls_status_t const status,
                                            ctls_hsmg_alert_type_t *alert_type,
                                            ctls_hsmg_alert_level_t *alert_level) {
    CTLS_CHECK_NULL(alert_type);
    CTLS_CHECK_NULL(alert_level);

    *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;

    switch (status) {
        case CTLS_STATUS_SUCCESS:
            return CTLS_STATUS_INVALID_ARG;

        /*
         * Direct alert-type mapping (bug 4 fix). CTLS_STATUS_ALERT_* are hook
         * return values, not derived from another failure — one status code
         * per ctls_hsmg_alert_type_t value, so this maps 1:1 with no
         * ambiguity. close_notify and user_canceled are the only two
         * RFC 8446 §6.2 alerts sent at WARNING level; every other alert is
         * FATAL, which *alert_level already defaults to above.
         */
        case CTLS_STATUS_ALERT_CLOSE_NOTIFY:
            *alert_type = CTLS_HSMG_ALERT_TYPE_CLOSE_NOTIFY;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_WARNING;
            break;
        case CTLS_STATUS_ALERT_UNEXPECTED_MESSAGE:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNEXPECTED_MESSAGE;
            break;
        case CTLS_STATUS_ALERT_BAD_RECORD_MAC:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_RECORD_MAC;
            break;
        case CTLS_STATUS_ALERT_RECORD_OVERFLOW:
            *alert_type = CTLS_HSMG_ALERT_TYPE_RECORD_OVERFLOW;
            break;
        case CTLS_STATUS_ALERT_HANDSHAKE_FAILURE:
            *alert_type = CTLS_HSMG_ALERT_TYPE_HANDSHAKE_FAILURE;
            break;
        case CTLS_STATUS_ALERT_BAD_CERTIFICATE:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE;
            break;
        case CTLS_STATUS_ALERT_UNSUPPORTED_CERTIFICATE:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_CERTIFICATE;
            break;
        case CTLS_STATUS_ALERT_CERTIFICATE_REVOKED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_CERTIFICATE_REVOKED;
            break;
        case CTLS_STATUS_ALERT_CERTIFICATE_EXPIRED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_CERTIFICATE_EXPIRED;
            break;
        case CTLS_STATUS_ALERT_CERTIFICATE_UNKNOWN:
            *alert_type = CTLS_HSMG_ALERT_TYPE_CERTIFICATE_UNKNOWN;
            break;
        case CTLS_STATUS_ALERT_ILLEGAL_PARAMETER:
            *alert_type = CTLS_HSMG_ALERT_TYPE_ILLEGAL_PARAMETER;
            break;
        case CTLS_STATUS_ALERT_UNKNOWN_CA:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNKNOWN_CA;
            break;
        case CTLS_STATUS_ALERT_ACCESS_DENIED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_ACCESS_DENIED;
            break;
        case CTLS_STATUS_ALERT_DECODE_ERROR:
            *alert_type = CTLS_HSMG_ALERT_TYPE_DECODE_ERROR;
            break;
        case CTLS_STATUS_ALERT_DECRYPT_ERROR:
            *alert_type = CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR;
            break;
        case CTLS_STATUS_ALERT_PROTOCOL_VERSION:
            *alert_type = CTLS_HSMG_ALERT_TYPE_PROTOCOL_VERSION;
            break;
        case CTLS_STATUS_ALERT_INSUFFICIENT_SECURITY:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INSUFFICIENT_SECURITY;
            break;
        case CTLS_STATUS_ALERT_INTERNAL_ERROR:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INTERNAL_ERROR;
            break;
        case CTLS_STATUS_ALERT_INAPPROPRIATE_FALLBACK:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INAPPROPRIATE_FALLBACK;
            break;
        case CTLS_STATUS_ALERT_USER_CANCELED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_USER_CANCELED;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_WARNING;
            break;
        case CTLS_STATUS_ALERT_MISSING_EXTENSION:
            *alert_type = CTLS_HSMG_ALERT_TYPE_MISSING_EXTENSION;
            break;
        case CTLS_STATUS_ALERT_UNSUPPORTED_EXTENSION:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_EXTENSION;
            break;
        case CTLS_STATUS_ALERT_UNRECOGNIZED_NAME:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNRECOGNIZED_NAME;
            break;
        case CTLS_STATUS_ALERT_BAD_CERTIFICATE_STATUS:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE_STATUS;
            break;
        case CTLS_STATUS_ALERT_UNKNOWN_PSK_IDENTITY:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNKNOWN_PSK_IDENTITY;
            break;
        case CTLS_STATUS_ALERT_CERTIFICATE_REQUIRED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_CERTIFICATE_REQUIRED;
            break;
        case CTLS_STATUS_ALERT_NO_APPLICATION_PROTOCOL:
            *alert_type = CTLS_HSMG_ALERT_TYPE_NO_APPLICATION_PROTOCOL;
            break;

        /* unexpected_message(10) — wrong message type or out-of-order record */
        case CTLS_STATUS_RECD_INVALID_CONTENT_TYPE:
        case CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE:
        case CTLS_STATUS_RECD_INVALID_MSG_TYPE:
        case CTLS_STATUS_RECD_EPOCH_MISMATCH:
        case CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH:
        case CTLS_STATUS_RECD_DESER_STANDALONE_MSG:
        case CTLS_STATUS_RECD_DESER_UNKNOWN_MSG:
        case CTLS_STATUS_HSMG_UNKNOWN_MSG_TYPE:
        /* NOTE: CTLS_STATUS_HSMG_INVALID_MSG_TYPE ==
         * CTLS_STATUS_HSMG_CH_INVALID_WIRE_FORMAT (0x0161) */
        case CTLS_STATUS_HSMG_INVALID_MSG_TYPE:
        case CTLS_STATUS_EXTN_UNKNOWN_MSG_TYPE:
        case CTLS_STATUS_HSHK_INVALID_STATE:
        case CTLS_STATUS_HSHK_ALREADY_CONNECTED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNEXPECTED_MESSAGE;

            break;

        /* bad_record_mac(20) — AEAD tag verification failed */
        case CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_RECORD_MAC;
            break;

        /* record_overflow(22) — record exceeds maximum permitted size */
        case CTLS_STATUS_BUFFER_OVERFLOW:
        case CTLS_STATUS_BOUNDS_EXCEEDED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_RECORD_OVERFLOW;
            break;

        /* handshake_failure(40) — negotiation could not proceed */
        case CTLS_STATUS_CRYPTO_ECDH_FAILED:
        case CTLS_STATUS_CRYPTO_UNSUPPORTED_CIPHER_SUITE:
        case CTLS_STATUS_CRYPTO_UNSUPPORTED_DHE_GROUP:
        case CTLS_STATUS_RECD_NO_MUTUAL_AUTH:
        case CTLS_STATUS_RECD_CR_NO_MUTUAL_AUTH:
        case CTLS_STATUS_TMPL_UNKNOWN_PROFILE:
            *alert_type = CTLS_HSMG_ALERT_TYPE_HANDSHAKE_FAILURE;
            break;

        /* bad_certificate(42) — certificate parse or public key import failed */
        case CTLS_STATUS_CRYPTO_CERT_SPKI_NOT_FOUND:
        case CTLS_STATUS_CRYPTO_CERT_KEY_PAIR_IMPORT_FAILED:
        case CTLS_STATUS_CRYPTO_CERT_PUB_KEY_IMPORT_FAILED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE;
            break;

        /* illegal_parameter(47) — value violates protocol or template constraints */
        case CTLS_STATUS_RECD_UNSUPPORTED_CID:
        case CTLS_STATUS_EXTN_INVALID_ENTITY_OWNERSHIP:
        case CTLS_STATUS_EXTN_INVALID_ENTITY:
        case CTLS_STATUS_EXTN_CERT_STATUS_INVALID_ENTITY:
        case CTLS_STATUS_EXTN_CERT_CREATE_INVALID_ENTITY:
        case CTLS_STATUS_TMPL_INVALID_PROFILE_ID:
        case CTLS_STATUS_TMPL_INVALID_PROTOCOL_VERSION:
        case CTLS_STATUS_TMPL_INVALID_CIPHER_SUITE:
        case CTLS_STATUS_TMPL_INVALID_DHE_GROUP:
        case CTLS_STATUS_TMPL_INVALID_SIG_ALGORITHM:
        case CTLS_STATUS_TMPL_INVALID_KNOWN_CERTIFICATES:
        case CTLS_STATUS_TMPL_INVALID_EXTENSION:
        case CTLS_STATUS_TMPL_UNKNOWN_ELEMENT:
        case CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_EXPECTED:
        case CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_SELF_DELIM:
            *alert_type = CTLS_HSMG_ALERT_TYPE_ILLEGAL_PARAMETER;
            break;

        /* decode_error(50) — malformed message; peer sent structurally invalid data */
        case CTLS_STATUS_BUFFER_TOO_SMALL:
        case CTLS_STATUS_RECD_INVALID_SEQ_LEN:
        case CTLS_STATUS_RECD_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_HDR_DESERIALIZE_CID:
        case CTLS_STATUS_RECD_HDR_DESERIALIZE_SEQ:
        case CTLS_STATUS_RECD_CH_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_SH_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_EE_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_CR_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_CERT_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_CV_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_FIN_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_SF_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_RECD_CF_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_SH_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_EE_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_CR_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_CERT_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_CV_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_HSMG_FIN_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_EXTN_INVALID_SIZE_FLAG:
        case CTLS_STATUS_EXTN_INVALID_FORM:
        case CTLS_STATUS_EXTN_INVALID_STATUS_TYPE:
        case CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_EXTN_DESER_ENUM_SIZE_FLAG:
        case CTLS_STATUS_EXTN_ALPN_INVALID_FORM:
        case CTLS_STATUS_EXTN_CERT_AUTH_INVALID_FORM:
        case CTLS_STATUS_EXTN_CH_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_EXTN_SH_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_EXTN_EE_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_EXTN_CR_INVALID_WIRE_FORMAT:
        case CTLS_STATUS_EXTN_CERT_INVALID_WIRE_FORMAT:
            *alert_type = CTLS_HSMG_ALERT_TYPE_DECODE_ERROR;
            break;

        /* decrypt_error(51) — signature or Finished HMAC verification failed */
        case CTLS_STATUS_CRYPTO_INVALID_SIGNATURE:
        case CTLS_STATUS_CRYPTO_SIGNATURE_VERIFY_FAILED:
        case CTLS_STATUS_CRYPTO_HMAC_VERIFY_DATA_FAILED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR;
            break;

        /* insufficient_security(71) — algorithm rejected as too weak */
        case CTLS_STATUS_CRYPTO_NOT_SUPPORTED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INSUFFICIENT_SECURITY;
            break;

        /* unsupported_extension(110) — extension not recognised or not permitted here */
        case CTLS_STATUS_EXTN_UNKNOWN_TYPE:
        case CTLS_STATUS_EXTN_UNEXPECTED_EXPECTED_EXTNS:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_EXTENSION;
            break;

        /* internal_error(80) — implementation bug or crypto subsystem failure;
         * covers NULL args, key schedule failures, hash failures, etc. */
        default:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INTERNAL_ERROR;
            break;
    }

    return CTLS_STATUS_SUCCESS;
}

/**
 * @brief Map status to alert type/level, send the alert, then return the
 *        original status.
 *
 * Called once from a handshake driver's onerror path (bug 4 fix — hooks
 * return a CTLS_STATUS_ALERT_* code instead of sending an alert themselves,
 * so exactly one alert is ever sent per failure). Clears the record, maps
 * status via ctls_status_to_alert_type_map, builds and serializes the alert
 * record, and writes it to the transport. Any step failing (map, build,
 * serialize, or transport send) returns that step's error immediately —
 * this is NOT best-effort/silent. On success returns status unchanged so
 * the caller still sees the original failure, not CTLS_STATUS_SUCCESS.
 *
 * @param record  Scratch record, cleared and reused to build the alert.
 * @param status  Original failure status to map and report back.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects write key/IV).
 * @param phase   Handshake phase (selects plaintext vs encrypted framing).
 * @return status on success (alert sent), or the first error encountered
 *         while mapping/building/sending the alert.
 */

ctls_status_t ctls_alert_send(ctls_record_t *record,
                              ctls_status_t const status,
                              ctls_entity_t const entity,
                              ctls_phase_t const phase) {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;
    ctls_status_t result = CTLS_STATUS_SUCCESS;
    ctls_hsmg_alert_type_t alert_type;
    ctls_hsmg_alert_level_t alert_level;

    result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_status_to_alert_type_map(status, &alert_type, &alert_level);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_recd_alert_create(record, alert_type, alert_level);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_recd_alert_to_wire(buffer, &buffer_offset, record, entity, phase);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* Alert consumes one sequence number just like any other record. */
    result = ctls_sequence_number_counter_increment();
    if (result != CTLS_STATUS_SUCCESS) return result;

    return status;
}
