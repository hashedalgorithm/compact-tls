//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#include "ctls/templates.h"

const ctls_template_t ctls_template_1 = {
    .profile_id = 0x01,
    .ctls_version = 0x00,
    .protocol_version = 0x0304, // TLS 1.3
    .cipher_suite = 0x1301, // CTLS_CIPHER_SUITE_AES_128_CCM_8_SHA256
    .dhe_group = {.key_share_length = CTLS_WIRE_KEY_SHARE, .dhe_group = 0x001D},
    // CTLS_DHE_GROUP_X25519
    .signature_algorithm = {
        .signature_algorithm_type = 0x0807,
        .signature_length = CTLS_WIRE_SIGNATURE,
    }, // CTLS_SIGNATURE_ALGORITHM_ED25519
    .random = 32U,
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
    },
    .finished_size = 64U
};


