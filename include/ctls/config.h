//
// Created by Sanjay Kumar Kumaravelan on 03/04/26.
//

/**
 * @file config.h
 * @brief Compile-time configuration: role, profile constants, template data.
 *
 * cTLS connections run from a "template" both peers agree on out of band
 * (draft-ietf-tls-ctls): the template predefines protocol parameters so they
 * never travel on the wire. This header fixes the build's role
 * (client/server), the sizes implied by the chosen profile's algorithms, and
 * the initializer for the built-in template.
 */

#ifndef CTLS_CONFIG_H
#define CTLS_CONFIG_H

#include "certs/ctls_certs.h"

/** cTLS template/encoding version this build speaks. */
#define CTLS_VERSION 0x0A

/*
 * Role selection at compile time — exactly one of these is 1. Constrained
 * targets only ever play one role, so the other side's code paths (key
 * selection, message direction checks) compile out entirely.
 */
#define CTLS_CLIENT  1
#define CTLS_SERVER  0

// default profile parameters — mandatory when CTLS_CLIENT is active

/*
 * Sizes implied by profile 0x01's algorithm choices
 * (TLS_AES_128_GCM_SHA256 + x25519, see CTLS_TEMPLATE_1_INIT below).
 * These change if the template picks a different hash/cipher/group.
 */
#define CTLS_SIZE_RANDOM  32U              /* Hello random, RFC 8446 §4.1.2 */
#define CTLS_SIZE_HASH 32U                 /* SHA-256 output */
#define CTLS_SIZE_AEAD_KEY 16U             /* AES-128-GCM key */
#define CTLS_SIZE_AEAD_TAG 16U             /* GCM auth tag, RFC 5116 */
#define CTLS_SIZE_IV 12U                   /* AEAD nonce/IV, RFC 8446 §5.3 */
#define CTLS_SIZE_KEY_SHARE  32U           /* x25519 public key, RFC 7748 */
#define CTLS_SIZE_CERTIFICATE_REQUEST_CONTEXT 1U
#define CTLS_SIZE_SCT_LOG_ID 32U           /* SCT LogID, RFC 6962 §3.2 */
#define CTLS_SIZE_SIGNED_BYTES  64U
#define CTLS_COUNT_KNOWN_CERTIFICATES  2
#define CTLS_SIZE_TICKET_NONCE 8U
#define CTLS_SIZE_TICKET 32U
#define CTLS_SIZE_PSK_IDENTITY 64U
#define CTLS_SIZE_PSK_BINDER CTLS_SIZE_HASH
#define CTLS_ENTITY_CERTIFICATE_ID 0x01    /* this build's own cert in the dictionary */


/* Using a wrong profile with wrong parameters results in connection
 * failure. Refer profile-registry.md for profile definitions. */

#define CTLS_PROFILE_ID 0x01    // Refer profile-registry.md to get respective profileId
#define CTLS_DEFAULT_CIPHER_SUITE  0x1301   /* TLS_AES_128_GCM_SHA256, RFC 8446 §B.4 */
#define CTLS_DEFAULT_SIGNATURE_LENGTH 32U
#define CTLS_DEFAULT_FINISHED_LENGTH 64U
#define CTLS_DEFAULT_SENTINEL 0xFFFF        /* template field "not set" */

/*
 * Built-in template, profile 0x01 — initializer for ctls_template_t
 * (see templates.h for field semantics). Pins:
 *
 *   protocol_version    0x0304  TLS 1.3
 *   cipher_suite        0x1301  TLS_AES_128_GCM_SHA256
 *   dhe_group           0x001D  x25519, key share length fixed at 32
 *   signature_algorithm 0x0807  ed25519 (RFC 8446 §4.2.3)
 *   expected_extensions 0x0033  key_share — the one extension that travels
 *                               on the wire in CH and SH
 *   known_certificates          certificate dictionary: full DER stored
 *                               here, only the 1-byte id crosses the wire
 *
 * mutual_auth / handshake_framing are left at CTLS_DEFAULT_SENTINEL (unset).
 */
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
    .known_certificates = {                                                             \
        .entries = {                                                                    \
            [0] = { .certificate_id = 0x01,                                             \
                    .certificate = server_cert_der,                                     \
                    .certificate_length = (uint16_t) sizeof(server_cert_der) },         \
            [1] = { .certificate_id = 0x02,                                             \
                    .certificate = client_cert_der,                                     \
                    .certificate_length = (uint16_t) sizeof(client_cert_der) },         \
        }                                                                               \
    },                                                                                  \
    .finished_size        = CTLS_DEFAULT_FINISHED_LENGTH,                               \
}


#endif
