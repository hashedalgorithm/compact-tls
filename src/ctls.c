#include<string.h>
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


ctls_template_t const *ctls_template_get(void) { return g_template; }
ctls_hshk_data_t *ctls_hshk_data_get(void) { return g_hshk_data; }
ctls_crypto_t *ctls_crypto_get(void) { return g_crypto; }
ctls_hshk_buffer_t *ctls_hshk_buffer_get(void) { return g_hshk_buffer; }
ctls_transport_t *ctls_transport_get(void) { return g_transport; }
ctls_record_t *ctls_record_get(void) { return g_record; }


ctls_status_t ctls_handshake_state_update(ctls_hshk_state_t *location,
                                          ctls_hshk_state_t const state) {
    CTLS_CHECK_NULL(location);
    *location = state;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_validate_template() {
    ctls_template_t const *template = g_template;
    if (!template) return CTLS_STATUS_TMPL_NULL;

    if (template->cipher_suite == 0) return CTLS_STATUS_TMPL_INVALID_CIPHER_SUITE;
    if (template->dhe_group.dhe_group == 0) return CTLS_STATUS_TMPL_INVALID_DHE_GROUP;
    if (template->signature_algorithm.signature_algorithm_type == 0)
        return CTLS_STATUS_TMPL_INVALID_SIG_ALGORITHM;
    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_wire_buffer_clear(uint8_t *buffer, ctls_size_t *buffer_offest) {
    CTLS_CHECK_NULL_BUFFER(buffer);
    CTLS_CHECK_NULL_OFFSET(buffer_offest);

    memset(buffer, 0, CTLS_SIZE_WIRE_BUFFER);
    *buffer_offest = 0;

    return CTLS_STATUS_SUCCESS;
}

ctls_status_t ctls_context_init(ctls_context_t *context,
                                ctls_transport_t const *transport) {
    memset(context, 0, sizeof(ctls_context_t));
    memset(&context->record, 0, sizeof(ctls_record_t));
    memset(&g_hshk_buffer_storage, 0, sizeof(g_hshk_buffer_storage));

    ctls_status_t result = ctls_template_set(CTLS_PROFILE_ID, context);
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

    result = ctls_core_handshake_state_update(CTLS_HSHK_STATE_START);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_validate_template();
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

    result = context->transport.recd_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_client_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Server Hello
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_SERVER_HELLO,
                                     buffer,
                                     buffer_offset);
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
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_SERVER_FLIGHT,
                                     buffer,
                                     buffer_offset);
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

        result = context->transport.recd_send(buffer, buffer_offset);
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

    if (result == CTLS_STATUS_SENT_ALERT) return result;

    return ctls_alert_from_status(&context->record,
                                  result,
                                  CTLS_ENTITY_CLIENT,
                                  CTLS_PHASE_HANDSHAKE);
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
    ctls_status_t result = context->transport.recd_receive(buffer,
                                                           &buffer_offset,
                                                           sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_CLIENT_HELLO,
                                     buffer);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_client_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_transcript_hash_update(&context->record, CTLS_HSMG_TYPE_CLIENT_HELLO);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    context->state = CTLS_HSHK_STATE_WAIT_SERVER_HELLO;

    // Server Hello
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_recd_server_hello_create(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_serialize(&context->record,
                                   CTLS_HSMG_TYPE_SERVER_HELLO,
                                   buffer,
                                   &buffer_offset,
                                   CTLS_ENTITY_SERVER);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = context->transport.recd_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_transcript_hash_update(&context->record, CTLS_HSMG_TYPE_SERVER_HELLO);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    context->state = CTLS_HSHK_STATE_KEY_SCHEDULED;

    // Key schedule
    result = ctls_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    context->state = CTLS_HSHK_STATE_WAIT_ENCRYPTED_EXTENSIONS;
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

    result = context->transport.recd_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_transcript_hash_update(&context->record, CTLS_HSMG_TYPE_SERVER_FLIGHT);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Client Flight (mutual auth)
    if (context->template->mutual_auth == 1) {
        result = ctls_wire_buffer_clear(buffer, &buffer_offset);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_record_deserialize(&context->record,
                                         CTLS_HSMG_TYPE_CLIENT_FLIGHT,
                                         buffer);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_core_client_flight_op(&context->record);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_transcript_hash_update(&context->record,
                                             CTLS_HSMG_TYPE_CLIENT_FLIGHT);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;
    }

    result = ctls_application_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    context->state = CTLS_HSHK_STATE_CONNECTED;
    context->hshk_data.isHandshakeComplete = true;

    return CTLS_STATUS_SUCCESS;

onerror:
    context->state = CTLS_HSHK_STATE_ERROR;
    ctls_recd_buffer_clear(&context->record);
    ctls_wire_buffer_clear(buffer, &buffer_offset);
    return result;
}
#endif /* CTLS_SERVER */


ctls_status_t ctls_connect(ctls_context_t *context) {
    ctls_status_t const result = ctls_validate_template();
    if (result != CTLS_STATUS_SUCCESS) return result;

#if CTLS_CLIENT
    return ctls_handshake(context);
#else
    (void) context; return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

ctls_status_t ctls_accept(ctls_context_t *context) {
    ctls_status_t const result = ctls_validate_template();
    if (result != CTLS_STATUS_SUCCESS) return result;

#if CTLS_SERVER
    return ctls_server_handshake(context);
#else
    (void) context;
    return CTLS_STATUS_NOT_IMPLEMENTED;
#endif
}

ctls_status_t ctls_read(uint8_t *buffer,
                        uint8_t *application_data,
                        ctls_size_t const application_data_length,
                        ctls_entity_t const entity) {
    ctls_transport_t const *transport = ctls_transport_get();

    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_STRUCT(transport);

    ctls_size_t buffer_offset = 0;
    ctls_status_t result = transport->recd_receive(buffer,
                                                   &buffer_offset,
                                                   CTLS_SIZE_WIRE_BUFFER);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_recd_application_data_deserialize(buffer,
                                                  application_data,
                                                  application_data_length,
                                                  entity);
}

ctls_status_t ctls_write(uint8_t const *application_data,
                         ctls_size_t const application_data_length,
                         ctls_entity_t const entity) {
    ctls_transport_t const *transport = ctls_transport_get();
    ctls_record_t const *record = ctls_record_get();

    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_STRUCT(transport);
    CTLS_CHECK_NULL_STRUCT(record);

    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;

    ctls_status_t const result = ctls_recd_application_data_serialize(buffer,
        &buffer_offset,
        application_data,
        application_data_length,
        entity);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return transport->recd_send(buffer, buffer_offset);
}


ctls_status_t ctls_status_to_alert_type_map(ctls_status_t const status,
                                            ctls_hsmg_alert_type_t *alert_type,
                                            ctls_hsmg_alert_level_t *alert_level) {
    CTLS_CHECK_NULL(alert_type);
    CTLS_CHECK_NULL(alert_level);

    switch (status) {
        case CTLS_STATUS_SUCCESS:
            return CTLS_STATUS_INVALID_ARG;

        /* unexpected_message(10) — wrong message type or out-of-order record */
        case CTLS_STATUS_RECD_INVALID_CONTENT_TYPE:
        case CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE:
        case CTLS_STATUS_RECD_INVALID_MSG_TYPE:
        case CTLS_STATUS_RECD_EPOCH_MISMATCH:
        case CTLS_STATUS_RECD_SEQUENCE_NUMBER_MISMATCH:
        case CTLS_STATUS_RECD_DESER_STANDALONE_MSG:
        case CTLS_STATUS_RECD_DESER_UNKNOWN_MSG:
        case CTLS_STATUS_HSMG_UNKNOWN_MSG_TYPE:
        /* NOTE: CTLS_STATUS_HSMG_INVALID_MSG_TYPE == CTLS_STATUS_HSMG_CH_INVALID_WIRE_FORMAT (0x0161) */
        case CTLS_STATUS_HSMG_INVALID_MSG_TYPE:
        case CTLS_STATUS_EXTN_UNKNOWN_MSG_TYPE:
        case CTLS_STATUS_HSHK_INVALID_STATE:
        case CTLS_STATUS_HSHK_ALREADY_CONNECTED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNEXPECTED_MESSAGE;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* bad_record_mac(20) — AEAD tag verification failed */
        case CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_RECORD_MAC;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* record_overflow(22) — record exceeds maximum permitted size */
        case CTLS_STATUS_BUFFER_OVERFLOW:
        case CTLS_STATUS_BOUNDS_EXCEEDED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_RECORD_OVERFLOW;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* handshake_failure(40) — negotiation could not proceed */
        case CTLS_STATUS_CRYPTO_ECDH_FAILED:
        case CTLS_STATUS_CRYPTO_UNSUPPORTED_CIPHER_SUITE:
        case CTLS_STATUS_CRYPTO_UNSUPPORTED_DHE_GROUP:
        case CTLS_STATUS_RECD_NO_MUTUAL_AUTH:
        case CTLS_STATUS_RECD_CR_NO_MUTUAL_AUTH:
        case CTLS_STATUS_TMPL_UNKNOWN_PROFILE:
            *alert_type = CTLS_HSMG_ALERT_TYPE_HANDSHAKE_FAILURE;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* bad_certificate(42) — certificate parse or public key import failed */
        case CTLS_STATUS_CRYPTO_CERT_SPKI_NOT_FOUND:
        case CTLS_STATUS_CRYPTO_CERT_KEY_PAIR_IMPORT_FAILED:
        case CTLS_STATUS_CRYPTO_CERT_PUB_KEY_IMPORT_FAILED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* illegal_parameter(47) — value violates protocol or template constraints */
        case CTLS_STATUS_RECD_UNSUPPORTED_CID:
        case CTLS_STATUS_EXTN_INVALID_ENTITY_OWNERSHIP:
        case CTLS_STATUS_EXTN_INVALID_ENTITY:
        case CTLS_STATUS_EXTN_CERT_STATUS_INVALID_ENTITY:
        case CTLS_STATUS_EXTN_CERT_CREATE_INVALID_ENTITY:
        case CTLS_STATUS_TMPL_INVALID_CIPHER_SUITE:
        case CTLS_STATUS_TMPL_INVALID_DHE_GROUP:
        case CTLS_STATUS_TMPL_INVALID_SIG_ALGORITHM:
        case CTLS_STATUS_TMPL_INVALID_EXTENSION:
        case CTLS_STATUS_TMPL_UNKNOWN_ELEMENT:
        case CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_EXPECTED:
        case CTLS_STATUS_TMPL_EXTN_KEY_SHARE_IN_SELF_DELIM:
            *alert_type = CTLS_HSMG_ALERT_TYPE_ILLEGAL_PARAMETER;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
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
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* decrypt_error(51) — signature or Finished HMAC verification failed */
        case CTLS_STATUS_CRYPTO_INVALID_SIGNATURE:
        case CTLS_STATUS_CRYPTO_SIGNATURE_VERIFY_FAILED:
        case CTLS_STATUS_CRYPTO_HMAC_VERIFY_DATA_FAILED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* insufficient_security(71) — algorithm rejected as too weak */
        case CTLS_STATUS_CRYPTO_NOT_SUPPORTED:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INSUFFICIENT_SECURITY;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* unsupported_extension(110) — extension not recognised or not permitted here */
        case CTLS_STATUS_EXTN_UNKNOWN_TYPE:
        case CTLS_STATUS_EXTN_UNEXPECTED_EXPECTED_EXTNS:
            *alert_type = CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_EXTENSION;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;

        /* internal_error(80) — implementation bug or crypto subsystem failure;
         * covers NULL args, key schedule failures, hash failures, etc. */
        default:
            *alert_type = CTLS_HSMG_ALERT_TYPE_INTERNAL_ERROR;
            *alert_level = CTLS_HSMG_ALERT_LEVEL_FATAL;
            break;
    }

    return CTLS_STATUS_SUCCESS;
}

/*
 * Send a fatal encrypted alert (RFC 8446 §6) over the transport.
 * Inner plaintext layout: level(1) | description(1) | content_type_alert(1).
 * Best-effort: caller has already decided to return an error, so a send
 * failure here is silently ignored.
 */

ctls_status_t ctls_alert_send(ctls_record_t *record,
                              ctls_hsmg_alert_type_t const alert_type,
                              ctls_hsmg_alert_level_t const alert_level,
                              ctls_entity_t const entity,
                              ctls_phase_t const phase) {
    ctls_transport_t const *transport = ctls_transport_get();

    CTLS_CHECK_NULL_STRUCT(transport);


    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;
    ctls_status_t result = CTLS_STATUS_SUCCESS;

    result = ctls_recd_buffer_clear(record);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_recd_alert_create(record, alert_type, alert_level);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = ctls_recd_alert_to_wire(buffer, &buffer_offset, record, entity, phase);
    if (result != CTLS_STATUS_SUCCESS) return result;

    result = transport->recd_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) return result;

    /* Alert consumes one sequence number just like any other record. */
    ctls_sequence_number_counter_increment();

    return CTLS_STATUS_SENT_ALERT;
}

ctls_status_t ctls_alert_from_status(ctls_record_t *record,
                                     ctls_status_t const status,
                                     ctls_entity_t const entity,
                                     ctls_phase_t const phase) {
    CTLS_CHECK_NULL_STRUCT(record);

    ctls_status_t result = CTLS_STATUS_SUCCESS;

    ctls_hsmg_alert_type_t alert_type;
    ctls_hsmg_alert_level_t alert_level;

    /*
     * Map ctls_status_t → TLS 1.3 alert (RFC 8446 §6).
     * In TLS 1.3 every alert except close_notify and user_canceled is FATAL.
     * close_notify / user_canceled are not triggered by error paths, so all
     * cases here use FATAL level.
     */
    result = ctls_status_to_alert_type_map(status, &alert_type, &alert_level);
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_alert_send(record, alert_type, alert_level, entity, phase);
}
