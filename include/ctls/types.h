
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
#define CTLS_HSHK_BUFFER_SIZE 512U

#define CTLS_WIRE_CONTENT_TYPE 1U
#define CTLS_WIRE_SEQUENCE_NUMBER 8U
#define CTLS_WIRE_LENGTH 2U

#define CTLS_WIRE_PROFILE_ID 1U
#define CTLS_WIRE_RANDOM 32U
#define CTLS_WIRE_KEY_SHARE 32U
#define CTLS_WIRE_SIGNATURE 64U
#define CTLS_WIRE_VERIFY_DATA 32U
#define CTLS_WIRE_SERVER_NAME 64U
#define CTLS_WIRE_ALPN 12U
#define CTLS_WIRE_ALPN_COUNT 3
#define CTLS_WIRE_SERVER_NAME_COUNT 3

#define CTLS_SIZE_TRANSCRIPT_HASH 32U

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
    CTLS_HSMG_CIPHER_SUITE_AES_128_GCM_SHA256 = 0x1301,
    CTLS_HSMG_CIPHER_SUITE_AES_256_GCM_SHA384 = 0x1302,
    CTLS_HSMG_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 = 0x1303,
    CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_SHA256 = 0x1304,
    CTLS_HSMG_CIPHER_SUITE_AES_128_CCM_8_SHA256 = 0x1305,
} ctls_hsmg_cipher_suite_type_t;

typedef enum {
    CTLS_EXTN_DHE_GROUP_SECP256R1 = 0x0017,
    CTLS_EXTN_DHE_GROUP_SECP384R1 = 0x0018,
    CTLS_EXTN_DHE_GROUP_SECP521R1 = 0x0019,
    CTLS_EXTN_DHE_GROUP_X25519 = 0x001D,
    CTLS_EXTN_DHE_GROUP_X448 = 0x001E,
    CTLS_EXTN_DHE_GROUP_FFDHE2048 = 0x0100,
    CTLS_EXTN_DHE_GROUP_FFDHE3072 = 0x0101,
    CTLS_EXTN_DHE_GROUP_FFDHE4096 = 0x0102,
} ctls_extn_dhe_group_type_t;

typedef enum {
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
} ctls_extn_signature_algorithm_type_t;

typedef enum {
    CTLS_HSMG_PROTOCOL_VERSION_1_2 = 0x0303,
    CTLS_HSMG_PROTOCOL_VERSION_1_3 = 0x0304,
} ctls_hsmg_protocol_version_t;

typedef enum {
    CTLS_RECD_CONTENT_TYPE_INVALID = 0x00,
    CTLS_RECD_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14,
    CTLS_RECD_CONTENT_TYPE_ALERT = 0x15,
    CTLS_RECD_CONTENT_TYPE_HANDSHAKE = 0x16,
    CTLS_RECD_CONTENT_TYPE_APPLICATION_DATA = 0x17,
    CTLS_RECD_CONTENT_TYPE_HEARTBEAT = 0x18,
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

typedef enum {
    CTLS_OP_STATUS_SUCCESS = 100,
    CTLS_OP_STATUS_FAIL,
    CTLS_OP_STATUS_UNKNOWN,
    CTLS_OP_STATUS_OVERFLOW,
    CTLS_OP_STATUS_INVALID,
    CTLS_OP_STATUS_ERROR,
} ctls_op_status_code_t;

typedef enum {
    CTLS_ERROR_SOURCE_CRYPTO = 0,
    CTLS_ERROR_SOURCE_INTERNAL,
    CTLS_ERROR_SOURCE_TRANSPORT,
} ctls_error_source_t;

typedef enum {
    CTLS_HSMG_PSK_PSK_ONLY = 0x00,
    CTLS_HSMG_PSK_PSK_WITH_DHE_KEY = 0x01,
} ctls_hsmg_psk_key_exchange_mode_t;

typedef enum {
    CTLS_EXTN_CERTIFICATE_TYPE_X509 = 0x00,
    CTLS_EXTN_CERTIFICATE_TYPE_RAW_PUBLIC_KEY = 0x02,
} ctls_extn_certificate_type_t;

typedef enum {
    CTLS_RECORD_TYPE_PLAINTEXT = 0,
    CTLS_RECORD_TYPE_ENCRYPTED,
} ctls_record_type_t;

typedef enum {
    CTLS_EXTN_HOST_NAME = 0x00,
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
    CTLS_EXTN_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND = 1,
    CTLS_EXTN_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND = 2,
} ctls_extn_heartbeat_mode_t;

typedef enum {
    CTLS_WIRE_FORMAT_DEFAULT = 0,
    CTLS_WIRE_FORMAT_TRANSCRIPT_HASH = 1,
} ctls_wire_format_t;

typedef enum {
    CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_PSK_KEY = 0,
    CTLS_EXTN_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KEY = 1,
} ctls_extn_psk_key_exchange_mode_t;


typedef struct ctls_hshk_buffer_block ctls_hshk_buffer_block_t;

typedef uint16_t ctls_extn_maximum_fragment_length_t;

typedef uint8_t ctls_extn_post_handshake_auth_t;

typedef struct ctls_extn_server_name ctls_extn_server_name_t;
typedef struct ctls_extn_server_name_list ctls_extn_server_name_list_t;
typedef struct ctls_extn_certificate_status_request
ctls_extn_certificate_status_request_t;
typedef struct ctls_extn_ocsp_status_request ctls_extn_ocsp_status_request_t;
typedef struct ctls_extn_alpn ctls_extn_alpn_t;

typedef struct ctls_hsmg_client_hello ctls_hsmg_client_hello_t;
typedef struct ctls_extn_client_hello ctls_extn_client_hello_t;
typedef struct ctls_extn_supported_groups
ctls_extn_supported_groups_t;
typedef struct ctls_extn_supported_version
ctls_extn_supported_version_t;
typedef struct ctls_extn_signature_algorithm
ctls_extn_signature_algorithm_t;
typedef struct ctls_extn_key_share ctls_extn_key_share_t;


typedef struct ctls_hsmg_server_hello ctls_hsmg_server_hello_t;
typedef struct ctls_hsmg_encrypted_extensions ctls_hsmg_encrypted_extensions_t;
typedef struct ctls_hsmg_certificate ctls_hsmg_certificate_t;
typedef struct ctls_hsmg_certificate_verify ctls_hsmg_certificate_verify_t;
typedef struct ctls_hsmg_finished ctls_hsmg_finished_t;
typedef struct ctls_hsmg_application_data ctls_hsmg_application_data_t;
typedef struct ctls_hsmg_alert ctls_hsmg_alert_t;


typedef struct ctls_record ctls_record_t;
typedef struct ctls_recd_config_octet ctls_recd_config_octet_t;
typedef struct ctls_handshake_message ctls_handshake_message_t;

typedef struct ctls_op_status ctls_op_status_t;

typedef struct ctls_template ctls_template_t;
typedef struct ctls_template_bytes ctls_template_bytes_t;
typedef struct ctls_tmpl_signature_algorithm ctls_tmpl_signature_algorithm_t;
typedef struct ctls_tmpl_dhe_group ctls_tmpl_dhe_group_t;
typedef struct ctls_tmpl_extensions ctls_tmpl_extensions_t;
typedef struct ctls_tmpl_predefined_extensions
ctls_tmpl_predefined_extensions_t;
typedef struct ctls_tmpl_extension ctls_tmpl_extension_t;
typedef ctls_extn_type_t ctls_tmpl_expected_extensions_t[4];
typedef ctls_extn_type_t ctls_tmpl_self_delimiting_extensions_t[4];


#if CTLS_CLIENT
#endif

#if CTLS_SERVER
#endif


typedef struct ctls_context ctls_context_t;
typedef struct ctls_transport ctls_transport_t;
typedef struct ctls_transcript_hash ctls_transcript_hash_t;


/* ------------------------------------------------------------------ */
/*  VIRTUAL FUNCTIONS                                                 */
/* ------------------------------------------------------------------ */

typedef ctls_op_status_t (*ctls_recd_send)(uint8_t *buffer,
                                           size_t buffer_length);
typedef ctls_op_status_t (*ctls_recd_receive)(uint8_t *buffer,
                                              size_t *buffer_length,
                                              size_t buffer_size);

#endif
