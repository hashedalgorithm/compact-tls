#include <string.h>
#include "ctls/ctls.h"
#include "ctls/templates.h"

ctls_hshk_buffer_t hshk_buffer;


ctls_op_status_t ctls_handshake_state_update(ctls_hshk_state_t *location,
                                             ctls_hshk_state_t const state) {
    CTLS_CHECK_NULL(location);
    *location = state;

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

ctls_op_status_t ctls_validate_template(ctls_template_t const *template) {
    CTLS_CHECK_NULL(template);

    if (template->cipher_suite == 0 || template->dhe_group.dhe_group == 0 || template->
        signature_algorithm.signature_algorithm_type == 0)
        return (ctls_op_status_t){
            .source = CTLS_ERROR_SOURCE_INTERNAL,
            .code = CTLS_OP_STATUS_INVALID,
            .external_code = CTLS_OP_STATUS_INVALID,
        };
    // TODO
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}

void ctls_wire_buffer_clear(uint8_t *buffer) {
    memset(buffer, 0, 256);
}

ctls_op_status_t ctls_context_init(ctls_context_t *context,
                                   ctls_transport_t const *transport) {
    memset(context, 0, sizeof(ctls_context_t));
    memset(&context->record, 0, sizeof(ctls_record_t));
    memset(&hshk_buffer, 0, sizeof(hshk_buffer));

    ctls_template_set(CTLS_PROFILE_ID, context);
    context->transport = *transport;

    ctls_crypto_init(&context->crypto, context->template, &context->hshk_data);

    context->state = CTLS_HSHK_STATE_START;

    return ctls_validate_template(context->template);
}


ctls_op_status_t ctls_handshake(ctls_context_t *context) {
    uint8_t buffer[CTLS_SIZE_WIRE_BUFFER];
    ctls_size_t buffer_length = 0;

    ctls_op_status_t result = ctls_transcript_hash_init(&context->crypto,
                                                        context->hshk_data.
                                                        transcript_hash,
                                                        context->template);

    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }


    // 1. build new ClientHello into context->record
    result = ctls_recd_client_hello_create(&context->record,
                                           context->template,
                                           &context->hshk_data,
                                           &context->crypto);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    // 2. serialize record to wire bytes
    result = ctls_record_serialize(context->template,
                                   &context->record,
                                   buffer,
                                   sizeof(buffer),
                                   &buffer_length);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        ctls_wire_buffer_clear(buffer);
        return result;
    }

    ctls_handshake_state_update(&context->state, CTLS_HSHK_STATE_ERROR);
    // clears the buffer for next step
    ctls_wire_buffer_clear(buffer);

    // 3. send
    result = context->transport.recd_send(buffer, buffer_length);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        ctls_handshake_state_update(&context->state, CTLS_HSHK_STATE_ERROR);
        return result;
    }

    ctls_transcript_hash_update(&context->record,
                                context->template,
                                &context->crypto.transcript_hash_operator,
                                context->hshk_data.transcript_hash);

    context->state = CTLS_HSHK_STATE_WAIT_SERVER_HELLO;
    // 4. recv — blocks until server responds
    ctls_size_t recv_len = 0;
    memset(buffer, 0, CTLS_SIZE_WIRE_BUFFER);
    result = context->transport.recd_receive(buffer, &recv_len, sizeof(buffer));
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    // 5. deserialize into record
    ctls_recd_buffer_clear(&context->record);
    result = ctls_record_deserialize(&context->record,
                                     context->template,
                                     &context->hshk_data,
                                     CTLS_HSMG_TYPE_SERVER_HELLO,
                                     buffer,
                                     recv_len);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    ctls_transcript_hash_update(&context->record,
                                context->template,
                                &context->crypto.transcript_hash_operator,
                                context->hshk_data.transcript_hash);

    context->state = CTLS_HSHK_STATE_KEY_SCHEDULED;

    // 6. Key scheduling
    result = ctls_key_schedule(&context->crypto, &context->hshk_data);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;


    context->state = CTLS_HSHK_STATE_WAIT_ENCRYPTED_EXTENSIONS;
    // 7. Receive encrypted extensions
    recv_len = 0;
    memset(buffer, 0, CTLS_SIZE_WIRE_BUFFER);
    result = context->transport.recd_receive(buffer, &recv_len, sizeof(buffer));
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE;
    ctls_recd_buffer_clear(&context->record);
    result = ctls_record_deserialize(&context->record,
                                     context->template,
                                     &context->hshk_data,
                                     CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS,
                                     buffer,
                                     recv_len);
    if (result.code != CTLS_OP_STATUS_SUCCESS) {
        context->state = CTLS_HSHK_STATE_ERROR;
        return result;
    }

    ctls_transcript_hash_update(&context->record,
                                context->template,
                                &context->crypto.transcript_hash_operator,
                                context->hshk_data.transcript_hash);

    if (context->template->mutual_auth == 1) {
        // 8. Receive Certificate Request
        recv_len = 0;
        memset(buffer, 0, CTLS_SIZE_WIRE_BUFFER);
        result = context->transport.recd_receive(buffer, &recv_len, sizeof(buffer));
        if (result.code != CTLS_OP_STATUS_SUCCESS) {
            context->state = CTLS_HSHK_STATE_ERROR;
            return result;
        }


        context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY;
        ctls_recd_buffer_clear(&context->record);
        result = ctls_record_deserialize(&context->record,
                                         context->template,
                                         &context->hshk_data,
                                         CTLS_HSMG_TYPE_CERTIFICATE_REQUEST,
                                         buffer,
                                         recv_len);
        if (result.code != CTLS_OP_STATUS_SUCCESS) {
            context->state = CTLS_HSHK_STATE_ERROR;
            return result;
        }

        context->state = CTLS_HSHK_STATE_WAIT_CERTIFICATE;
        ctls_transcript_hash_update(&context->record,
                                    context->template,
                                    &context->crypto.transcript_hash_operator,
                                    context->hshk_data.transcript_hash);
    }


    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_SUCCESS,
        .external_code = CTLS_OP_STATUS_SUCCESS,
    };
}


ctls_op_status_t ctls_connect(ctls_context_t *context) {
    ctls_op_status_t const result = ctls_validate_template(context->template);
    if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

    return ctls_handshake(context);
}
