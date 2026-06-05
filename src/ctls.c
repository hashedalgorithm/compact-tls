#include <string.h>
#include "ctls/ctls.h"
#include "ctls/templates.h"

static ctls_template_t const *g_template;
static ctls_hshk_data_t *g_hshk_data;
static ctls_crypto_t *g_crypto;
static ctls_hshk_buffer_t *g_hshk_buffer;
static ctls_hshk_buffer_t g_hshk_buffer_storage;


ctls_template_t const *ctls_template_get(void) { return g_template; }
ctls_hshk_data_t *ctls_hshk_data_get(void) { return g_hshk_data; }
ctls_crypto_t *ctls_crypto_get(void) { return g_crypto; }
ctls_hshk_buffer_t *ctls_hshk_buffer_get(void) { return g_hshk_buffer; }


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

    result = ctls_crypto_init();
    if (result != CTLS_STATUS_SUCCESS) return result;

    context->state = CTLS_HSHK_STATE_START;

    return ctls_validate_template();
}


ctls_status_t ctls_handshake(ctls_context_t *context) {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_offset = 0;

    ctls_status_t result = ctls_recd_client_hello_create(&context->record);
    if (result != CTLS_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    result = ctls_record_serialize(&context->record, buffer, &buffer_offset);

    result = context->transport.recd_send(buffer, buffer_offset);
    context->state = CTLS_HSHK_STATE_WAIT_SERVER_HELLO;
    // Server Hello
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_SERVER_HELLO,
                                     buffer,
                                     recv_len);
    if (result != CTLS_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    ctls_transcript_hash_update(&context->record);

    context->state = CTLS_HSHK_STATE_KEY_SCHEDULED;

    result = ctls_key_schedule(&context->crypto, &context->hshk_data);
    if (result != CTLS_STATUS_SUCCESS) return result;


    context->state = CTLS_HSHK_STATE_WAIT_ENCRYPTED_EXTENSIONS;
    result = ctls_wire_buffer_clear(buffer, &buffer_offset);
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE;

    // Encrypted Extensions
    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                                     buffer,
                                     recv_len);
    if (result != CTLS_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    ctls_transcript_hash_update(&context->record);

    if (context->template->mutual_auth == 1 && context->template->signature_algorithm.
        signature_algorithm_type == CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL) {
        result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));

        context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY;
        ctls_recd_buffer_clear(&context->record);
        result = ctls_record_deserialize(&context->record,
                                         CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                                         buffer,
                                         recv_len);
        if (result != CTLS_STATUS_SUCCESS) {
            context->state = CTLS_HSHK_STATE_ERROR;
            return result;
        }

        context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE;
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    result = ctls_record_deserialize(&context->record,
                                     CTLS_HSMG_TYPE_CERTIFICATE,
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));
    result = context->transport.recd_receive(buffer, &buffer_offset, sizeof(buffer));

    result = ctls_transcript_hash_update(&context->record);
    if (result != CTLS_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }


}


ctls_status_t ctls_connect(ctls_context_t *context) {
    ctls_status_t const result = ctls_validate_template();
    if (result != CTLS_STATUS_SUCCESS) return result;

    return ctls_handshake(context);
}
