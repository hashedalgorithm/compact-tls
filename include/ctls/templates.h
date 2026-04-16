//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#ifndef CTLS_TEMPLATES_H
#define CTLS_TEMPLATES_H

#include <stddef.h>
#include "internal.h"
#include "types.h"

#if CTLS_CLIENT
static const ctls_template_t ctls_template_1 = {
    .profile_id = 0x01,
    .ctls_version = 0x00,
    .protocol_version = 0x0304, // TLS 1.3
    .random = 32U,
    .dhe_group = 0x001D, // CTLS_DHE_GROUP_X25519
    .cipher_suite = 0x1301, // CTLS_CIPHER_SUITE_AES_128_CCM_8_SHA256
    .signature_algorithm = 0x0807, // CTLS_SIGNATURE_ALGORITHM_ED25519
    .mutual_auth = 0,
    .handshake_framing = 0,
    .extensions = {
        .client_hello_extension = {
            .allow_additional = 0,
            .expected_extensions = {CTLS_EXTN_TYPE_KEY_SHARE},
        },
        .server_hello_extension = {
            .allow_additional = 0,
            .expected_extensions = {CTLS_EXTN_TYPE_KEY_SHARE},
        },
        .encrypted_extension = {
            .allow_additional = 0
        }
    }
};

static inline ctls_op_status_t ctls_set_template(
    uint8_t const profile_id, ctls_template_t *template) {
    switch (profile_id) {
        case 0x01: {
            template = &ctls_template_1;
            return (ctls_op_status_t) (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_SUCCESS,
                .external_code = CTLS_OP_STATUS_SUCCESS,
            };
        }
        default: {
            template = NULL;
            return (ctls_op_status_t){
                .source = CTLS_ERROR_SOURCE_INTERNAL,
                .code = CTLS_OP_STATUS_INVALID,
                .external_code = CTLS_OP_STATUS_INVALID,
            };
        }
    }
}

#endif


#if CTLS_SERVER
static const ctls_template_t CTLS_PROFILES[] = {
    // AES-128-GCM + X25519 + ECDSA_P256
    {
        .profile_id = 0x01,
        .version = CTLS_VERSION_1_3,
        .cipher_suite = CTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        .dhe_group = CTLS_DHE_GROUP_X25519,
        .signature_algorithm = CTLS_SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256,
        .certificate = NULL,
        .certificate_length = 0,
    },
    // AES-128-GCM + SECP256R1 + ECDSA_P256
    {
        .profile_id = 0x02,
        .version = CTLS_VERSION_1_3,
        .cipher_suite = CTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        .dhe_group = CTLS_DHE_GROUP_SECP256R1,
        .signature_algorithm = CTLS_SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256,
        .certificate = NULL,
        .certificate_length = 0,
    },
};

#endif


#endif
