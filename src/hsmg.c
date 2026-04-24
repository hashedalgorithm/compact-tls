//
// Created by SanjayKumar Kumaravelan on 16/04/26.
//

#include <string.h>
#include "ctls/bytes.h"
#include "ctls/ctls.h"
#include "ctls/extensions.h"
#include "ctls/hsmg.h"
#include "ctls/templates.h"


ctls_op_status_t ctls_hsmg_client_hello_to_struct() {
}

ctls_op_status_t ctls_hsmg_client_hello_to_wire() {
}

ctls_op_status_t ctls_hsmg_server_hello_create() {
}

ctls_op_status_t ctls_hsmg_server_hello_to_struct() {
}

ctls_op_status_t ctls_hsmg_server_hello_to_wire() {
}

ctls_op_status_t ctls_hsmg_encrypted_extensions_create() {
}

ctls_op_status_t ctls_hsmg_encrypted_extensions_to_struct() {
}

ctls_op_status_t ctls_hsmg_encrypted_extensions_to_wire() {
}

ctls_op_status_t ctls_hsmg_certificate_create() {
}

ctls_op_status_t ctls_hsmg_certificate_to_struct() {
}

ctls_op_status_t ctls_hsmg_certificate_to_wire() {
}

ctls_op_status_t ctls_hsmg_certificate_verify_create() {
}

ctls_op_status_t ctls_hsmg_certificate_verify_to_struct() {
}

ctls_op_status_t ctls_hsmg_certificate_verify_to_wire() {
}

ctls_op_status_t ctls_hsmg_finished_create() {
}

ctls_op_status_t ctls_hsmg_finished_to_struct() {
}

ctls_op_status_t ctls_hsmg_finished_to_wire() {
}


ctls_op_status_t ctls_hsmg_client_hello_create(ctls_handshake_message_t *hsmg,
                                               ctls_template_t const *
                                               template) {
        ctls_hsmg_random_t random;
        ctls_op_status_t result = ctls_random_generate(random);
        if (result.code != CTLS_OP_STATUS_SUCCESS) return result;

        hsmg->handshake_message_body.client_hello.cipher_suite =
                        template->cipher_suite;
        hsmg->handshake_message_body.client_hello.protocol_version =
                        template->protocol_version;
        hsmg->handshake_message_body.client_hello.legacy_session_id =
                        0x00;
        hsmg->handshake_message_body.client_hello.
                        legacy_compression_methods = 0x00;

        memcpy(&hsmg->handshake_message_body.client_hello.random,
               random, template->random);

        return ctls_extn_client_hello_create(
                &hsmg->handshake_message_body.client_hello, template);
}

