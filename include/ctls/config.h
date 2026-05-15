//
// Created by Sanjay Kumar Kumaravelan on 03/04/26.
//

#ifndef CTLS_CONFIG_H
#define CTLS_CONFIG_H

#include "certs/ctls_certs.h"

#define CTLS_VERSION 0x0A
#define CTLS_CLIENT  1
#define CTLS_SERVER  0

// default profile parameters — mandatory when CTLS_CLIENT is active

// These sizes varies based on the hash type the template uses.
#define CTLS_SIZE_RANDOM  32U
#define CTLS_SIZE_HASH 32U
#define CTLS_SIZE_AEAD_KEY 16U
#define CTLS_SIZE_IV 12U
#define CTLS_SIZE_KEY_SHARE  32U


/* Using a wrong profile with wrong parameters results in connection
 * failure. Refer profile-registry.md for profile definitions. */

#define CTLS_PROFILE_ID 0x01    // Refer profile-registry.md to get respective profileId
#define CTLS_DEFAULT_CIPHER_SUITE  0x1301
#define CTLS_DEFAULT_SIGNATURE_LENGTH 32U
#define CTLS_DEFAULT_FINISHED_LENGTH 64U
#define CTLS_DEFAULT_SENTINEL 0xFFFF

#define CTLS_TEMPLATE_1_INIT {                                                          \
    .profile_id           = CTLS_PROFILE_ID,                                            \
    .ctls_version         = CTLS_VERSION,                                               \
    .protocol_version     = 0x0304,                                                     \
    .cipher_suite         = CTLS_DEFAULT_CIPHER_SUITE,                                  \
    .dhe_group            = { .key_share_length = CTLS_SIZE_KEY_SHARE,                  \
                              .dhe_group = 0x001D },                                    \
    .signature_algorithm  = { .signature_algorithm_type = 0x0807,                       \
                              .signature_length = CTLS_DEFAULT_SIGNATURE_LENGTH },      \
    .random               = CTLS_SIZE_RANDOM,                                           \
    .mutual_auth          = CTLS_DEFAULT_SENTINEL,                                      \
    .handshake_framing    = CTLS_DEFAULT_SENTINEL,                                      \
    .client_hello_extension = { .allow_additional = 0,                                  \
                                .expected_extensions = { 0x0033 } },                    \
    .server_hello_extension = { .allow_additional = 0,                                  \
                                .expected_extensions = { 0x0033 } },                    \
    .encrypted_extension  = { .allow_additional = 0 },                                  \
    .certificate_request_extension = { .allow_additional = 0 },                         \
    .known_certificate = {                                                              \
        "01" : client_cert_der                                                          \
    }                                                                                   \
    .finished_size        = CTLS_DEFAULT_FINISHED_LENGTH,                               \
}


#endif
