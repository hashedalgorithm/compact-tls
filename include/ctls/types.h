
//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//

#ifndef CTLS_TYPES_H
#define CTLS_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"

/* --------------------------------------------------------------------  */
/*  Naming Context Abbreviations                                         */
/*  wire - Wire Size                                                     */
/*  size - Size                                                          */
/*  hsmg - Handshake Message                                             */
/*  hshk - Handshake                                                     */
/*  recd - Record                                                        */
/*  tmpl - Template                                                      */
/*  extn - Extension                                                     */
/* --------------------------------------------------------------------  */


/* ------------------------------------------------------------------ */
/*  CONSTANTS                                                         */
/* ------------------------------------------------------------------ */

#define CTLS_SIZE_WIRE_BUFFER 256U

#define CTLS_PROFILE_ID_LENGTH 1U
#define CTLS_COUNT_ALPN 3U
#define CTLS_COUNT_SERVER_NAME 3U
#define CTLS_SIZE_MAX_ALPN_PROTOCOL_NAME 12U
#define CTLS_COUNT_SUPPORTED_GROUPS  3U
#define CTLS_COUNT_SIGNATURE_ALGORITHM  3U
#define CTLS_SIZE_MAX_DISTINGUISHED_NAME 128U
#define CTLS_COUNT_CERTIFICATE_ENTRY 3U

/* config_octet — RFC 9147 §4, used verbatim by cTLS-10 §2.2
 *
 * Bit  7   6   5   4   3   2   1   0
 *      0   0   1   C   S   L   E   E
 *      ─── fixed ──  │   │   │   └─┴─ epoch bits [1:0]
 *                    │   │   └─────── L: length present
 *                    │   └─────────── S: seq num length (0=8b, 1=16b)
 *                    └─────────────── C: connection ID present
 */

/* Fixed bits (bits 7–5) — must be 0b001 on every record */
#define CTLS_RECD_CONFIG_OCTET_FIXED_VALUE    0x20u   /* 0010 0000 */

/* Bit 4: Connection ID present */
#define CTLS_RECD_CONFIG_OCTET_C_MASK         0x10u   /* 0001 0000 */

/* Bit 3: Sequence number length (0=8-bit, 1=16-bit) */
#define CTLS_RECD_CONFIG_OCTET_S_MASK         0x08u   /* 0000 1000 */


/* Bit 2: Length field present */
#define CTLS_RECD_CONFIG_OCTET_L_MASK         0x04u   /* 0000 0100 */

/* Bits 1–0: Low 2 bits of epoch */
#define CTLS_RECD_CONFIG_OCTET_EPOCH_MASK     0x03u   /* 0000 0011 */


/* ------------------------------------------------------------------ */
/*  PRIMITIVES                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    CTLS_TMPL_TYPE_PROFILE_ID = 0x0000,
    CTLS_TMPL_TYPE_VERSION = 0x0001,
    CTLS_TMPL_TYPE_CIPHER_SUITE = 0x0002,
    CTLS_TMPL_TYPE_DH_GROUP = 0x0003,
    CTLS_TMPL_TYPE_SIGNATURE_ALGORITHM = 0x0004,
    CTLS_TMPL_TYPE_RANDOM = 0x0005,
    CTLS_TMPL_TYPE_MUTUAL_AUTH = 0x0006,
    CTLS_TMPL_TYPE_HANDSHAKE_FRAMING = 0x0007,
    CTLS_TMPL_TYPE_CLIENT_HELLO_EXTENSIONS = 0x0008,
    CTLS_TMPL_TYPE_SERVER_HELLO_EXTENSIONS = 0x0009,
    CTLS_TMPL_TYPE_ENCRYPTED_EXTENSIONS = 0x000A,
    CTLS_TMPL_TYPE_CERTIFICATE_REQUEST_EXTENSIONS = 0x000B,
    CTLS_TMPL_TYPE_KNOWN_CERTIFICATES = 0x000C,
    CTLS_TMPL_TYPE_FINISHED_SIZE = 0x000D,
    CTLS_TMPL_TYPE_OPTIONAL = 0xFFFF,
} ctls_tmpl_type_t;

typedef enum {
    CTLS_HSMG_CIPHER_SUITE_SENTINEL = 0x0000,
    CTLS_HSMG_CIPHER_SUITE_AES_128_GCM_SHA256 = 0x1301,
    CTLS_HSMG_CIPHER_SUITE_AES_256_GCM_SHA384 = 0x1302,
    CTLS_HSMG_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 = 0x1303,
    CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_SHA256 = 0x1304,
    CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_8_SHA256 = 0x1305,
} ctls_cipher_suite_t;

typedef enum {
    CTLS_EXTN_DHE_GROUP_SENTINEL = 0x0000,
    CTLS_EXTN_DHE_GROUP_SECP256R1 = 0x0017,
    CTLS_EXTN_DHE_GROUP_SECP384R1 = 0x0018,
    CTLS_EXTN_DHE_GROUP_SECP521R1 = 0x0019,
    CTLS_EXTN_DHE_GROUP_X25519 = 0x001D,
    CTLS_EXTN_DHE_GROUP_X448 = 0x001E,
    CTLS_EXTN_DHE_GROUP_FFDHE2048 = 0x0100,
    CTLS_EXTN_DHE_GROUP_FFDHE3072 = 0x0101,
    CTLS_EXTN_DHE_GROUP_FFDHE4096 = 0x0102,
} ctls_dhe_group_t;

typedef enum {
    CTLS_EXTN_SIGNATURE_ALGORITHM_SENTINEL = 0x0000,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256 = 0x0401,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA384 = 0x0501,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA512 = 0x0601,
    CTLS_EXTN_SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256 = 0x0403,
    CTLS_EXTN_SIGNATURE_ALGORITHM_ECDSA_SECP384R1_SHA384 = 0x0503,
    CTLS_EXTN_SIGNATURE_ALGORITHM_ECDSA_SECP521R1_SHA512 = 0x0603,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_RSAE_SHA256 = 0x0804,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_RSAE_SHA384 = 0x0805,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_RSAE_SHA512 = 0x0806,
    CTLS_EXTN_SIGNATURE_ALGORITHM_ED25519 = 0x0807,
    CTLS_EXTN_SIGNATURE_ALGORITHM_ED448 = 0x0808,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_PSS_SHA256 = 0x0809,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_PSS_SHA384 = 0x080A,
    CTLS_EXTN_SIGNATURE_ALGORITHM_RSA_PSS_PSS_SHA512 = 0x080B,
} ctls_signature_scheme_t;

typedef enum {
    CTLS_HSMG_PROTOCOL_VERSION_SENTINEL = 0x0000,
    CTLS_HSMG_PROTOCOL_VERSION_1_2 = 0x0303,
    CTLS_HSMG_PROTOCOL_VERSION_1_3 = 0x0304,
} ctls_protocol_version_t;

typedef enum {
    CTLS_RECD_CONTENT_TYPE_INVALID = 0x00,
    CTLS_RECD_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14,
    CTLS_RECD_CONTENT_TYPE_ALERT = 0x15,
    CTLS_RECD_CONTENT_TYPE_HANDSHAKE = 0x16,
    CTLS_RECD_CONTENT_TYPE_APPLICATION_DATA = 0x17,
    CTLS_RECD_CONTENT_TYPE_HEARTBEAT = 0x18,
    /* 28 - 30 is unassigned in IANA registry.
     * Since ContentType for template is not assigned, we are using 28 for this implementation.
     * https://arc.net/l/quote/voyphzxt
     */
    CTLS_RECD_CONTENT_TYPE_TEMPLATE = 0x28,
    CTLS_RECD_CONTENT_TYPE_SENTINEL = 0xFF, // default value (uninitialized)
} ctls_recd_content_type_t;

typedef enum {
    CTLS_HSMG_ALERT_LEVEL_WARNING = 1,
    CTLS_HSMG_ALERT_LEVEL_FATAL = 2,
} ctls_hsmg_alert_level_t;

typedef enum {
    CTLS_EXTN_TYPE_SERVER_NAME = 0x0000,
    CTLS_EXTN_TYPE_MAX_FRAGMENT_LENGTH = 0x0001,
    CTLS_EXTN_TYPE_STATUS_REQUEST = 0x0005,
    CTLS_EXTN_TYPE_SUPPORTED_GROUPS = 0x000A,
    CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS = 0x000D,
    CTLS_EXTN_TYPE_USE_SRTP = 0x000E,
    CTLS_EXTN_TYPE_HEARTBEAT = 0x000F,
    CTLS_EXTN_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010,
    CTLS_EXTN_TYPE_SIGNED_CERTIFICATE_TIMESTAMP = 0x0012,
    CTLS_EXTN_TYPE_CLIENT_CERTIFICATE_TYPE = 0x0013,
    CTLS_EXTN_TYPE_SERVER_CERTIFICATE_TYPE = 0x0014,
    CTLS_EXTN_TYPE_PADDING = 0x0015,
    CTLS_EXTN_TYPE_PRE_SHARED_KEY = 0x0029,
    CTLS_EXTN_TYPE_EARLY_DATA = 0x002A,
    CTLS_EXTN_TYPE_SUPPORTED_VERSIONS = 0x002B,
    CTLS_EXTN_TYPE_COOKIE = 0x002C,
    CTLS_EXTN_TYPE_PSK_KEY_EXCHANGE_MODES = 0x002D,
    CTLS_EXTN_TYPE_CERTIFICATE_AUTHORITIES = 0x002F,
    CTLS_EXTN_TYPE_OID_FILTERS = 0x0030,
    CTLS_EXTN_TYPE_POST_HANDSHAKE_AUTH = 0x0031,
    CTLS_EXTN_TYPE_SIGNATURE_ALGORITHMS_CERT = 0x0032,
    CTLS_EXTN_TYPE_KEY_SHARE = 0x0033,
    CTLS_EXTN_TYPE_SENTINEL = 0xFFFF, // default value (uninitialized)
} ctls_extn_type_t;

typedef enum {
    CTLS_HSMG_ALERT_TYPE_CLOSE_NOTIFY = 0,
    CTLS_HSMG_ALERT_TYPE_UNEXPECTED_MESSAGE = 10,
    CTLS_HSMG_ALERT_TYPE_BAD_RECORD_MAC = 20,
    CTLS_HSMG_ALERT_TYPE_RECORD_OVERFLOW = 22,
    CTLS_HSMG_ALERT_TYPE_HANDSHAKE_FAILURE = 40,
    CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE = 42,
    CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_CERTIFICATE = 43,
    CTLS_HSMG_ALERT_TYPE_CERTIFICATE_REVOKED = 44,
    CTLS_HSMG_ALERT_TYPE_CERTIFICATE_EXPIRED = 45,
    CTLS_HSMG_ALERT_TYPE_CERTIFICATE_UNKNOWN = 46,
    CTLS_HSMG_ALERT_TYPE_ILLEGAL_PARAMETER = 47,
    CTLS_HSMG_ALERT_TYPE_UNKNOWN_CA = 48,
    CTLS_HSMG_ALERT_TYPE_ACCESS_DENIED = 49,
    CTLS_HSMG_ALERT_TYPE_DECODE_ERROR = 50,
    CTLS_HSMG_ALERT_TYPE_DECRYPT_ERROR = 51,
    CTLS_HSMG_ALERT_TYPE_PROTOCOL_VERSION = 70,
    CTLS_HSMG_ALERT_TYPE_INSUFFICIENT_SECURITY = 71,
    CTLS_HSMG_ALERT_TYPE_INTERNAL_ERROR = 80,
    CTLS_HSMG_ALERT_TYPE_INAPPROPRIATE_FALLBACK = 86,
    CTLS_HSMG_ALERT_TYPE_USER_CANCELED = 90,
    CTLS_HSMG_ALERT_TYPE_MISSING_EXTENSION = 109,
    CTLS_HSMG_ALERT_TYPE_UNSUPPORTED_EXTENSION = 110,
    CTLS_HSMG_ALERT_TYPE_UNRECOGNIZED_NAME = 112,
    CTLS_HSMG_ALERT_TYPE_BAD_CERTIFICATE_STATUS = 113,
    CTLS_HSMG_ALERT_TYPE_UNKNOWN_PSK_IDENTITY = 115,
    CTLS_HSMG_ALERT_TYPE_CERTIFICATE_REQUIRED = 116,
    CTLS_HSMG_ALERT_TYPE_NO_APPLICATION_PROTOCOL = 120,
} ctls_hsmg_alert_type_t;

typedef enum {
    CTLS_HSMG_TYPE_CLIENT_HELLO = 0x01,
    CTLS_HSMG_TYPE_SERVER_HELLO = 0x02,
    CTLS_HSMG_TYPE_NEW_SESSION_TICKET = 0x04,
    CTLS_HSMG_TYPE_END_OF_EARLY_DATA = 0x05,
    CTLS_HSMG_TYPE_HELLO_RETRY_REQUEST = 0x06,
    CTLS_HSMG_TYPE_ENCRYPTED_EXTENSIONS = 0x08,
    CTLS_HSMG_TYPE_CERTIFICATE = 0x0B,
    CTLS_HSMG_TYPE_CERTIFICATE_REQUEST = 0x0D,
    CTLS_HSMG_TYPE_CERTIFICATE_VERIFY = 0x0F,
    CTLS_HSMG_TYPE_FINISHED = 0x14,
    CTLS_HSMG_TYPE_KEY_UPDATE = 0x18,
    CTLS_HSMG_TYPE_MESSAGE_HASH = 0xFE,
    // 27, 28 are not assigned in IINA - custom definition
    CTLS_HSMG_TYPE_CLIENT_FLIGHT = 0x27,
    CTLS_HSMG_TYPE_SERVER_FLIGHT = 0x28,
    CTLS_HSMG_TYPE_SENTINEL = 0xFF,
} ctls_hsmg_type_t;

typedef enum {
    CTLS_HSHK_STATE_START = 0, // context initialized, handshake not begun
    CTLS_HSHK_STATE_WAIT_SERVER_HELLO, // ClientHello sent, waiting ServerHello
    CTLS_HSHK_STATE_WAIT_ENCRYPTED_EXTENSIONS,
    // ServerHello received, waiting EncryptedExtensions
    CTLS_HSHK_STATE_WAIT_CERTIFICATE, // waiting for server Certificate
    CTLS_HSHK_STATE_WAIT_CERTIFICATE_VERIFY, // waiting for CertificateVerify
    CTLS_HSHK_STATE_WAIT_FINISHED, // waiting for server Finished
    CTLS_HSHK_STATE_KEY_SCHEDULED,
    // keys derived, about to send client Finished
    CTLS_HSHK_STATE_CONNECTED, // handshake complete, application data phase
    CTLS_HSHK_STATE_CLOSED, // connection closed cleanly
    CTLS_HSHK_STATE_ERROR, // unrecoverable error
} ctls_hshk_state_t;

/* ------------------------------------------------------------------ */
/*  STATUS TYPE + ERROR CODES                                         */
/*  uint16_t — range encodes subsystem for traceability               */
/*  0x0000        Success                                             */
/*  0x0001-0x0031 General / Parameter                                */
/*  0x0032-0x0063 Buffer / Memory                                     */
/*  0x0064-0x00C7 Crypto (PSA-backed)                                */
/*  0x00C8-0x012B Extension Ser/Deser                                */
/*  0x012C-0x015D Record Layer                                       */
/*  0x015E-0x018F Handshake Messages                                 */
/*  0x0190-0x01C1 Template / Profile                                 */
/*  0x01C2-0x01F3 Transport                                          */
/*  0x01F4-0x0225 Handshake State Machine                            */
/* ------------------------------------------------------------------ */

typedef uint16_t ctls_status_t;

/* Success */
#define CTLS_STATUS_SUCCESS                         ((ctls_status_t)0x0000u)

/* General / Parameter (0x0001-0x0031) */
#define CTLS_STATUS_NULL_PTR                        ((ctls_status_t)0x0001u)
#define CTLS_STATUS_NULL_BUFFER                     ((ctls_status_t)0x0002u)
#define CTLS_STATUS_NULL_OFFSET                     ((ctls_status_t)0x0003u)
#define CTLS_STATUS_NULL_STRUCT                     ((ctls_status_t)0x0004u)
#define CTLS_STATUS_INVALID_ARG                     ((ctls_status_t)0x0005u)
#define CTLS_STATUS_UNKNOWN                         ((ctls_status_t)0x0006u)
#define CTLS_STATUS_NOT_IMPLEMENTED                 ((ctls_status_t)0x0007u)

/* Buffer / Memory (0x0032-0x0063) */
#define CTLS_STATUS_BUFFER_OVERFLOW                 ((ctls_status_t)0x0032u)
#define CTLS_STATUS_BUFFER_TOO_SMALL                ((ctls_status_t)0x0033u)
#define CTLS_STATUS_BOUNDS_EXCEEDED                 ((ctls_status_t)0x0034u)

/* Crypto (0x0064-0x00C7) */
#define CTLS_STATUS_CRYPTO_INIT_FAILED              ((ctls_status_t)0x0064u)
#define CTLS_STATUS_CRYPTO_INVALID_SIGNATURE        ((ctls_status_t)0x0065u)
#define CTLS_STATUS_CRYPTO_INVALID_ARG              ((ctls_status_t)0x0066u)
#define CTLS_STATUS_CRYPTO_NOT_SUPPORTED            ((ctls_status_t)0x0067u)
#define CTLS_STATUS_CRYPTO_INSUFFICIENT_ENTROPY     ((ctls_status_t)0x0068u)
#define CTLS_STATUS_CRYPTO_KEY_GEN_FAILED           ((ctls_status_t)0x0069u)
#define CTLS_STATUS_CRYPTO_KEY_EXPORT_FAILED        ((ctls_status_t)0x006Au)
#define CTLS_STATUS_CRYPTO_ECDH_FAILED              ((ctls_status_t)0x006Bu)
#define CTLS_STATUS_CRYPTO_HKDF_FAILED              ((ctls_status_t)0x006Cu)
#define CTLS_STATUS_CRYPTO_HASH_FAILED              ((ctls_status_t)0x006Du)
#define CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED      ((ctls_status_t)0x006Eu)
#define CTLS_STATUS_CRYPTO_AEAD_ENCRYPT_FAILED      ((ctls_status_t)0x006Fu)
#define CTLS_STATUS_CRYPTO_UNSUPPORTED_CIPHER_SUITE ((ctls_status_t)0x0070u)
#define CTLS_STATUS_CRYPTO_UNSUPPORTED_DHE_GROUP    ((ctls_status_t)0x0071u)
#define CTLS_STATUS_CRYPTO_RANDOM_FAILED            ((ctls_status_t)0x0071u)
#define CTLS_STATUS_CRYPTO_SIGNATURE_FAILED         ((ctls_status_t)0x0072u)
#define CTLS_STATUS_CRYPTO_UNKNOWN                  ((ctls_status_t)0x0073u)

/* Extension Ser/Deser (0x00C8-0x012B) */
#define CTLS_STATUS_EXTN_INVALID_SIZE_FLAG          ((ctls_status_t)0x00C8u)
#define CTLS_STATUS_EXTN_INVALID_FORM               ((ctls_status_t)0x00C9u)
#define CTLS_STATUS_EXTN_UNKNOWN_TYPE               ((ctls_status_t)0x00CAu)
#define CTLS_STATUS_EXTN_UNKNOWN_MSG_TYPE           ((ctls_status_t)0x00CBu)
#define CTLS_STATUS_EXTN_INVALID_STATUS_TYPE        ((ctls_status_t)0x00CCu)
#define CTLS_STATUS_EXTN_INVALID_ENTITY_OWNERSHIP   ((ctls_status_t)0x00CDu)
#define CTLS_STATUS_EXTN_INVALID_WIRE_FORMAT        ((ctls_status_t)0x00CEu)
#define CTLS_STATUS_EXTN_UNEXPECTED_EXPECTED_EXTNS  ((ctls_status_t)0x00CFu)
#define CTLS_STATUS_EXTN_INVALID_ENTITY             ((ctls_status_t)0x00D0u)

/* Record Layer (0x012C-0x015D) */
#define CTLS_STATUS_RECD_UNSUPPORTED_CID            ((ctls_status_t)0x012Cu)
#define CTLS_STATUS_RECD_INVALID_SEQ_LEN            ((ctls_status_t)0x012Du)
#define CTLS_STATUS_RECD_INVALID_CONTENT_TYPE       ((ctls_status_t)0x012Eu)
#define CTLS_STATUS_RECD_INVALID_WIRE_FORMAT        ((ctls_status_t)0x012Fu)
#define CTLS_STATUS_RECD_UNKNOWN_MSG_TYPE           ((ctls_status_t)0x0130u)
#define CTLS_STATUS_RECD_NO_MUTUAL_AUTH             ((ctls_status_t)0x0131u)
#define CTLS_STATUS_RECD_INVALID_MSG_TYPE           ((ctls_status_t)0x0132u)
#define CTLS_STATUS_RECD_INVALID_ENTITY             ((ctls_status_t)0x0133u)

/* Handshake Messages (0x015E-0x018F) */
#define CTLS_STATUS_HSMG_INVALID_WIRE_FORMAT        ((ctls_status_t)0x015Eu)
#define CTLS_STATUS_HSMG_UNKNOWN_MSG_TYPE           ((ctls_status_t)0x015Fu)
#define CTLS_STATUS_HSMG_INVALID_ENTITY             ((ctls_status_t)0x0160u)

/* Template / Profile (0x0190-0x01C1) */
#define CTLS_STATUS_TMPL_NULL                       ((ctls_status_t)0x0190u)
#define CTLS_STATUS_TMPL_INVALID_CIPHER_SUITE       ((ctls_status_t)0x0191u)
#define CTLS_STATUS_TMPL_INVALID_DHE_GROUP          ((ctls_status_t)0x0192u)
#define CTLS_STATUS_TMPL_INVALID_SIG_ALGORITHM      ((ctls_status_t)0x0193u)
#define CTLS_STATUS_TMPL_UNKNOWN_PROFILE            ((ctls_status_t)0x0194u)
#define CTLS_STATUS_TMPL_INVALID_EXTENSION          ((ctls_status_t)0x0195u)
#define CTLS_STATUS_TMPL_UNKNOWN_ELEMENT            ((ctls_status_t)0x0196u)

/* Transport (0x01C2-0x01F3) */
#define CTLS_STATUS_TRANSPORT_SEND_FAILED           ((ctls_status_t)0x01C2u)
#define CTLS_STATUS_TRANSPORT_RECV_FAILED           ((ctls_status_t)0x01C3u)

/* Handshake State Machine (0x01F4-0x0225) */
#define CTLS_STATUS_HSHK_INVALID_STATE              ((ctls_status_t)0x01F4u)
#define CTLS_STATUS_HSHK_ALREADY_CONNECTED          ((ctls_status_t)0x01F5u)

typedef enum {
    CTLS_EXTN_CERTIFICATE_TYPE_X509 = 0x00,
    CTLS_EXTN_CERTIFICATE_TYPE_RAW_PUBLIC_KEY = 0x02,
    CTLS_EXTN_CERTIFICATE_TYPE_SENTINEL = 0xFF,
} ctls_extn_certificate_type_t;

typedef enum {
    CTLS_RECORD_TYPE_PLAINTEXT = 0,
    CTLS_RECORD_TYPE_ENCRYPTED,
} ctls_record_type_t;

typedef enum {
    CTLS_EXTN_HOST_NAME = 0x00,
    CTLS_EXTN_HOST_NAME_SENTINEL = 0xFF,
} ctls_extn_host_name_type_t;

typedef enum {
    CTLS_EXTN_FRAGMENT_LENGTH_512 = 1, // 2^9
    CTLS_EXTN_FRAGMENT_LENGTH_1024 = 2, // 2^10
    CTLS_EXTN_FRAGMENT_LENGTH_2048 = 3, // 2^11
    CTLS_EXTN_FRAGMENT_LENGTH_4096 = 4, // 2^12
} ctls_extn_fragment_length_t;

typedef enum {
    CTLS_EXTN_CERTIFICATE_STATUS_TYPE_OSCP = 1,
} ctls_extn_certificate_status_type_t;

typedef enum {
    CTLS_EXTN_HEARTBEAT_MODE_SENTINEL = 0,
    CTLS_EXTN_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND = 1,
    CTLS_EXTN_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND = 2,
} ctls_extn_heartbeat_mode_t;

typedef enum {
    CTLS_WIRE_FORMAT_DEFAULT = 0,
    CTLS_WIRE_FORMAT_TRANSCRIPT_HASH = 1,
} ctls_wire_format_t;

typedef enum {
    CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_PSK_KEY = 0x00,
    CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KEY = 0x01,
    CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_SENTINEL = 0xFF,
} ctls_extn_psk_key_exchange_mode_t;

typedef enum {
    CTLS_DATA_FORM_SENTINEL = 0,
    CTLS_DATA_FORM_OPAQUE = 1,
    CTLS_DATA_FORM_PARSED = 2,
} ctls_data_form_t;

typedef enum {
    CTLS_MAX_FRAGMENT_LENGTH_9 = 1,
    CTLS_MAX_FRAGMENT_LENGTH_10,
    CTLS_MAX_FRAGMENT_LENGTH_11,
    CTLS_MAX_FRAGMENT_LENGTH_12,
    CTLS_MAX_FRAGMENT_LENGTH_14,
} ctls_max_fragment_length_t;

typedef enum {
    CTLS_EXTN_SCT_VERSION_V1 = 0x00, // only defined version
} ctls_extn_sct_version_t;

typedef enum {
    CTLS_EXTN_SCT_SIG_TYPE_CERTIFICATE_TIMESTAMP = 0,
    CTLS_EXTN_SCT_SIG_TYPE_TREE_HASH = 1,
} ctls_extn_sct_signature_type_t;

typedef enum {
    CTLS_EXTN_SCT_ENTRY_TYPE_X509 = 0, // final certificate
    CTLS_EXTN_SCT_ENTRY_TYPE_PRECERT = 1, // pre-certificate
} ctls_extn_sct_entry_type_t;

typedef enum {
    CTLS_ENTITY_CLIENT = 0,
    CTLS_ENTITY_SERVER = 1,
} ctls_entity_t;

typedef struct ctls_extn_server_name_item ctls_extn_server_name_item_t;
typedef struct ctls_extn_server_name ctls_extn_server_name_t;
typedef ctls_max_fragment_length_t ctls_extn_max_fragment_length_t;
typedef struct ctls_extn_certificate_status_request_parsed
ctls_extn_certificate_status_request_parsed_t;
typedef struct ctls_extn_certificate_status_request
ctls_extn_certificate_status_request_t;
typedef struct ctls_extn_ocsp_status_request ctls_extn_ocsp_status_request_t;
typedef ctls_dhe_group_t ctls_extn_supported_group_t;
typedef ctls_signature_scheme_t ctls_extn_signature_algorithm_t;
typedef struct ctls_extn_alpn_protocol_name ctls_extn_alpn_protocol_name_t;
typedef struct ctls_extn_alpn ctls_extn_alpn_t;
typedef struct ctls_extn_signed_certificate_timestamp_parsed
ctls_extn_signed_certificate_timestamp_parsed_t;
typedef struct ctls_extn_signed_certificate_timestamp
ctls_extn_signed_certificate_timestamp_t;
typedef ctls_extn_certificate_type_t ctls_extn_client_certificate_type_t;
typedef ctls_extn_certificate_type_t ctls_extn_server_certificate_type_t;
typedef ctls_protocol_version_t ctls_extn_supported_version_t;
typedef struct ctls_extn_certificate_authorities ctls_extn_certificate_authorities_t;
typedef uint8_t ctls_extn_post_handshake_auth_t;
typedef ctls_signature_scheme_t ctls_extn_signature_algorithm_cert_t;
typedef uint8_t *ctls_extn_key_share_t;
typedef struct ctls_extn_early_data ctls_extn_early_data_t;

typedef struct ctls_extn_client_hello ctls_extn_client_hello_t;
typedef struct ctls_hsmg_client_hello ctls_hsmg_client_hello_t;

typedef struct ctls_extn_server_hello ctls_extn_server_hello_t;
typedef struct ctls_hsmg_server_hello ctls_hsmg_server_hello_t;

typedef struct ctls_extn_encrypted_extensions ctls_extn_encrypted_extensions_t;
typedef struct ctls_hsmg_encrypted_extensions ctls_hsmg_encrypted_extensions_t;

typedef struct ctls_extn_certificate_request ctls_extn_certificate_request_t;
typedef struct ctls_hsmg_certificate_request ctls_hsmg_certificate_request_t;

typedef struct ctls_extn_certificate ctls_extn_certificate_t;
typedef struct ctls_hsmg_certificate_entry ctls_hsmg_certificate_entry_t;
typedef struct ctls_hsmg_certificate ctls_hsmg_certificate_t;


typedef struct ctls_hsmg_certificate_verify ctls_hsmg_certificate_verify_t;
typedef struct ctls_hsmg_finished ctls_hsmg_finished_t;
typedef struct ctls_hsmg_application_data ctls_hsmg_application_data_t;
typedef struct ctls_hsmg_alert ctls_hsmg_alert_t;

typedef struct ctls_hsmg_server_flight ctls_hsmg_server_flight_t;
typedef struct ctls_hsmg_client_flight ctls_hsmg_client_flight_t;
typedef struct ctls_extn_new_session_ticket ctls_extn_new_session_ticket_t;
typedef struct ctls_hsmg_new_session_ticket ctls_hsmg_new_session_ticket_t;

typedef struct ctls_record ctls_record_t;
typedef struct ctls_unified_header ctls_unified_header_t;
typedef struct ctls_recd_config_octet ctls_recd_config_octet_t;
typedef struct ctls_handshake_message ctls_handshake_message_t;


typedef struct ctls_template ctls_template_t;
typedef struct ctls_template_bytes ctls_template_bytes_t;
typedef struct ctls_tmpl_signature_algorithm ctls_tmpl_signature_algorithm_t;
typedef struct ctls_tmpl_dhe_group ctls_tmpl_dhe_group_t;
typedef struct ctls_tmpl_predefined_extensions ctls_tmpl_predefined_extensions_t;
typedef struct ctls_tmpl_extension ctls_tmpl_extension_t;
typedef ctls_extn_type_t ctls_tmpl_expected_extensions_t[4];
typedef ctls_extn_type_t ctls_tmpl_self_delimiting_extensions_t[4];
typedef struct ctls_tmpl_known_certificate ctls_tmpl_known_certificate_t;
typedef struct ctls_tmpl_known_certificates ctls_tmpl_known_certificates_t;


#if CTLS_CLIENT
#endif

#if CTLS_SERVER
#endif


typedef struct ctls_context ctls_context_t;
typedef struct ctls_crypto ctls_crypto_t;
typedef struct ctls_transport ctls_transport_t;
typedef struct ctls_hshk_data ctls_hshk_data_t;

typedef uint16_t ctls_size_t;
typedef struct ctls_hshk_buffer ctls_hshk_buffer_t;
typedef struct ctls_hshk_buffer_block ctls_hshk_buffer_block_t;


/* ------------------------------------------------------------------ */
/*  VIRTUAL FUNCTIONS                                                 */
/* ------------------------------------------------------------------ */

typedef ctls_status_t (*ctls_recd_send)(uint8_t *buffer, ctls_size_t buffer_length);
typedef ctls_status_t (*ctls_recd_receive)(uint8_t *buffer,
                                           ctls_size_t *buffer_length,
                                           ctls_size_t buffer_size);

#endif
