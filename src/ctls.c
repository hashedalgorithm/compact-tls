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

    context->state = CTLS_HSHK_STATE_START;

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
ctls_status_t ctls_handshake(ctls_context_t *context) {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;

    // Client Hello
    ctls_status_t result = ctls_recd_client_hello_create(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_serialize(&context->record, buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = context->transport.recd_send(buffer, buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_transcript_hash_update(&context->record, CTLS_HSMG_TYPE_CLIENT_HELLO);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;
    context->state = CTLS_HSHK_STATE_WAIT_SERVER_HELLO;
    // Server Hello
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_SERVER_HELLO,
                                     buffer);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_server_hello_internal_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_transcript_hash_update(&context->record, CTLS_HSMG_TYPE_SERVER_HELLO);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    context->state = CTLS_HSHK_STATE_KEY_SCHEDULED;

    // Key schedule
    result = ctls_key_schedule();
    if (result != CTLS_STATUS_SUCCESS) return result;

    context->state = CTLS_HSHK_STATE_WAIT_ENCRYPTED_EXTENSIONS;
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Server Flight
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY;
    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_SERVER_FLIGHT,
                                     buffer);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_core_server_flight_op(&context->record);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    result = ctls_transcript_hash_update(&context->record, CTLS_HSMG_TYPE_SERVER_FLIGHT);
    if (result != CTLS_STATUS_SUCCESS) goto onerror;

    // Client Flight
    if (context->template->mutual_auth == 1) {
        result = ctls_recd_client_flight_create(&context->record);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_record_serialize(&context->record, buffer, &buffer_offset);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = context->transport.recd_send(buffer, buffer_offset);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_core_client_flight_op(&context->record);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;

        result = ctls_transcript_hash_update(&context->record,
                                             CTLS_HSMG_TYPE_CLIENT_FLIGHT);
        if (result != CTLS_STATUS_SUCCESS) goto onerror;
    }

    result = ctls_application_key_schedule(CTLS_ENTITY_CLIENT);
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


ctls_status_t ctls_connect(ctls_context_t *context) {
    ctls_status_t const result = ctls_validate_template();
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_handshake(context);
}

ctls_status_t ctls_read(uint8_t *buffer,
                        uint8_t *application_data,
                        ctls_size_t const application_data_length,
                        ctls_entity_t const entity) {
    ctls_transport_t const *transport = ctls_transport_get();
    ctls_record_t *record = ctls_record_get();

    CTLS_CHECK_NULL_BUFFER(application_data);
    CTLS_CHECK_NULL_STRUCT(transport);
    CTLS_CHECK_NULL_STRUCT(record);

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
