//
// Created by Sanjay Kumar Kumaravelan on 18/04/26.
//

#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/templates.h"
#include "ctls/bytes.h"


ctls_op_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer, size_t *offset,
                                                ctls_hsmg_client_hello_t *
                                                client_hello,
                                                ctls_wire_format_t
                                                wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }
    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_client_hello_to_struct(
    uint8_t *buffer, size_t *offset, ctls_hsmg_client_hello_t *
    client_hello, ctls_template_t const *template) {
}

ctls_op_status_t ctls_extn_client_hello_create(
    ctls_hsmg_client_hello_t *client_hello, ctls_template_t const *template) {
    ctls_op_status_t result;
    uint8_t const size_of_expected_extensions =
            sizeof(template->extensions.client_hello_extension.
                expected_extensions) / sizeof(template->extensions.
                client_hello_extension.expected_extensions[0]);

    for (uint8_t i = 0; i < size_of_expected_extensions; i++) {
        switch (template->extensions.client_hello_extension.expected_extensions[
            i]) {
            case CTLS_EXTN_TYPE_SERVER_NAME:
            case CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH:
            case CTLS_EXTN_TYPE_STATUS_REQUEST:
            case CTLS_EXTN_TYPE_USE_SRTP:
            case CTLS_EXTN_TYPE_HEARTBEAT:
            case CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            case CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP:
            case CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE:
            case CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE:
            case CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES:
            case CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES:
            case CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH:
            case CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT:
                // TODO
                break;

            case CTLS_EXTN_TYPE_OID_FILTERS: {
                if (CTLS_SERVER) {
                    // TODO
                }
                return (ctls_op_status_t){

                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_INVALID,
                    .external_code = CTLS_OP_STATUS_INVALID,
                };
            }

            case CTLS_EXTN_TYPE_KEY_SHARE: {
                result = ctls_ephemeral_public_key_generate(
                    client_hello->
                    extensions.
                    key_share_entity, CTLS_WIRE_KEY_SHARE);
                if (result.code != CTLS_OP_STATUS_SUCCESS) return result;
            }
            break;
            case CTLS_EXTN_TYPE_SUPPORTED_GROUPS:
            case CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS:
            case CTLS_EXTN_TYPE_PADDING:
            case CTLS_EXTN_TYPE_PRE_SHARED_KEY:
            case CTLS_EXTN_TYPE_EARLY_DATA:
            case CTLS_EXTN_TYPE_SUPPORTED_VERSIONS:
            case CTLS_EXTN_TYPE_COOKIE:
                return (ctls_op_status_t){
                    .source = CTLS_ERROR_SOURCE_INTERNAL,
                    .code = CTLS_OP_STATUS_INVALID,
                    .external_code = CTLS_OP_STATUS_INVALID,
                };
        }
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_server_hello_to_wire(
    uint8_t *buffer, size_t *offset,
    ctls_hsmg_server_hello_t *
    server_hello,
    ctls_wire_format_t const
    wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_server_hello_to_struct() {
}

ctls_op_status_t ctls_extn_server_hello_create(
    ctls_hsmg_server_hello_t *
    server_hello, ctls_template_t const *template) {
}

ctls_op_status_t ctls_extn_encrypted_extensions_to_wire(
    uint8_t *buffer, size_t *offset,
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_wire_format_t const wire_format) {
    if (wire_format == CTLS_WIRE_FORMAT_DEFAULT) {
    }
    if (wire_format == CTLS_WIRE_FORMAT_TRANSCRIPT_HASH) {
    }

    return (ctls_op_status_t){
        .source = CTLS_ERROR_SOURCE_INTERNAL,
        .code = CTLS_OP_STATUS_INVALID,
        .external_code = CTLS_OP_STATUS_INVALID,
    };
}

ctls_op_status_t ctls_extn_encrypted_extensions_to_struct() {
}

ctls_op_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions,
    ctls_template_t const *template) {
}

// ctls_op_status_t ctls_extn_client_hello_build(
//     ctls_hsmg_client_hello_t *client_hello, ctls_template_t const *template,
//     uint8_t *buffer, size_t *offset) {}
//     ctls_op_status_t ctls_thsh_extensions_build(
//         ctls_handshake_message_t *message,
//         ctls_template_t const *template,
//         ctls_hsmg_type_t const hsmg_type,
//         uint8_t *buffer, size_t *offset)
//     {
//         switch (hsmg_type) {
//             case CTLS_HSMG_TYPE_CLIENT_HELLO: {
//                 ctls_thsh_extensions_client_hello_build(
//                     message->handshake_message_body.client_hello, template,
//                     buffer,
//                     offset);
//             }
//             case CTLS_HSMG_TYPE_SERVER_HELLO: break;
//             case CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS: break;
//             default: return (ctls_op_status_t){
//                 .source = CTLS_ERROR_SOURCE_INTERNAL,
//                 .code = CTLS_OP_STATUS_INVALID,
//                 .external_code = CTLS_OP_STATUS_INVALID,
//             };
//         }
//     }




