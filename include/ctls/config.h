//
// Created by Sanjay Kumar Kumaravelan on 03/04/26.
//

#ifndef CTLS_CONFIG_H
#define CTLS_CONFIG_H

#define CTLS_VERSION 0x0A
#define CTLS_CLIENT  1
#define CTLS_SERVER  0

// default profile parameters — mandatory when CTLS_CLIENT is active

/* Using a wrong profile with wrong parameters results in connection
 * failure. Refer profile-registry.md for profile definitions. */

#define CTLS_PROFILE_ID 0x01    // Refer profile-registry.md to get respective profileId
#define CTLS_PROFILE_ID_LENGTH 1U
#define CTLS_DEFAULT_CIPHER_SUITE  0x1301
#define CTLS_DEFAULT_KEY_SHARE_LENGTH 32U
#define CTLS_DEFAULT_RANDOM_LENGTH 32U
#define CTLS_DEFAULT_SIGNATURE_LENGTH 32U
#define CTLS_DEFAULT_FINISHED_LENGTH 64U
#define CTLS_DEFAULT_SENTINEL 0xFFFF

#define CTLS_TEMPLATE_1_INIT {                                                          \
    .profile_id           = CTLS_PROFILE_ID,                                            \
    .ctls_version         = CTLS_VERSION,                                               \
    .protocol_version     = 0x0304,                                                     \
    .cipher_suite         = CTLS_DEFAULT_CIPHER_SUITE,                                  \
    .dhe_group            = { .key_share_length = CTLS_DEFAULT_KEY_SHARE_LENGTH,        \
                              .dhe_group = 0x001D },                                    \
    .signature_algorithm  = { .signature_algorithm_type = 0x0807,                       \
                              .signature_length = CTLS_DEFAULT_SIGNATURE_LENGTH },      \
    .random               = CTLS_DEFAULT_RANDOM_LENGTH,                                 \
    .mutual_auth          = CTLS_DEFAULT_SENTINEL,                                      \
    .handshake_framing    = CTLS_DEFAULT_SENTINEL,                                      \
    .client_hello_extension = { .allow_additional = 0,                                  \
                                .expected_extensions = { 0x0033 } },                    \
    .server_hello_extension = { .allow_additional = 0,                                  \
                                .expected_extensions = { 0x0033 } },                    \
    .encrypted_extension  = { .allow_additional = 0 },                                  \
    .finished_size        = CTLS_DEFAULT_FINISHED_LENGTH,                               \
}


#endif
