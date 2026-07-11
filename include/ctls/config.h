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
#ifndef CTLS_CLIENT
#define CTLS_CLIENT  1
#endif
#ifndef CTLS_SERVER
#define CTLS_SERVER  0
#endif

/*
 * Transport reliability — exactly one of these is 1. Selects between the
 * two wire behaviors draft-ietf-tls-ctls §2.2 defines for the unified
 * header's S bit and sequence number field:
 *
 *   RELIABLE (TCP-like, "Stream cTLS"): S bit cleared, sequence number
 *   omitted from the wire entirely — ordering is the transport's job.
 *   UNRELIABLE (UDP-like, "Datagram cTLS"): S bit keeps its DTLS 1.3
 *   meaning (1-byte vs 2-byte encoding), sequence number always sent.
 *
 * Also selects the cTLS HKDF label prefix (draft §2.3.2): "Sctls " for
 * reliable, "Dctls " for unreliable — see crypto.h's CTLS_LABEL_PREFIX.
 * Default is UNRELIABLE: examples/ use UDP sockets.
 */
#ifndef CTLS_STREAM
#define CTLS_STREAM    0
#endif
#ifndef CTLS_DATAGRAM
#define CTLS_DATAGRAM  1
#endif

// default profile parameters — mandatory when CTLS_CLIENT is active

/*
 * Sizes implied by profile 0x01's algorithm choices
 * (TLS_AES_128_GCM_SHA256 + x25519, see template.json / profile-registry.md).
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
#define CTLS_SIZE_CERTIFICATE_KEY_LENGTH 65U

/* jsmn token budget for ctls_template_from_json (templates.c) — bounds the
 * stack-allocated jsmntok_t array parsing a profile-registry.md-schema
 * document; no heap allocation. */
#define CTLS_SIZE_JSON_TOKENS 96U

#define CTLS_SIZE_JSON_BUFFER 4096U

/* Per-entry capacity for known_certificates decoded from JSON hex text
 * (templates.c's ctls_tmpl_json_cert_storage) — largest cert here is
 * server_cert_der at 534 bytes (ctls_certs.h); headroom for a bigger one. */
#define CTLS_SIZE_KNOWN_CERTIFICATE_MAX 700U


/* Using a wrong profile with wrong parameters results in connection
 * failure. Refer profile-registry.md for profile definitions. */

#define CTLS_PROFILE_ID 0x01    // Refer profile-registry.md to get respective profileId
#define CTLS_DEFAULT_CIPHER_SUITE  0x1301   /* TLS_AES_128_GCM_SHA256, RFC 8446 §B.4 */
#define CTLS_DEFAULT_SIGNATURE_LENGTH 32U
#define CTLS_DEFAULT_FINISHED_LENGTH 64U
#define CTLS_DEFAULT_SENTINEL 0xFFFF        /* template field "not set" */



#endif
