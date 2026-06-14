//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

/**
 * @file extensions.h
 * @brief TLS 1.3 extension handling, compressed per cTLS (Compact TLS).
 *
 * References:
 *   - RFC 8446 — TLS 1.3 (extension framing and most definitions, Section 4.2)
 *   - RFC 6066 — server_name, max_fragment_length, status_request
 *   - RFC 7301 — application_layer_protocol_negotiation (ALPN)
 *   - RFC 6520 — heartbeat
 *   - RFC 6962 — signed_certificate_timestamp (SCT)
 *   - RFC 7250 — client_certificate_type / server_certificate_type
 *   - draft-ietf-tls-ctls — Compact TLS, "isomorphic to TLS 1.3 but saves
 *     space by aggressive use of defaults and tighter encodings"
 *
 * # Design: template compression
 *
 * In TLS 1.3 every extension travels on the wire as (RFC 8446, Section 4.2):
 *
 *     struct {
 *         ExtensionType extension_type;        // u16
 *         opaque extension_data<0..2^16-1>;    // u16 length + data
 *     } Extension;
 *
 * In cTLS both peers share a profile template that predefines most extension
 * values, so those extensions are never sent: the receiver reconstructs them
 * from its own copy of the template. Only dynamic data (e.g. key_share)
 * actually crosses the wire, stripped of any framing the template already
 * implies (known type, known length).
 *
 * The TLS 1.3 byte form is still needed in one place: the handshake
 * transcript. Both sides re-expand each handshake message into TLS 1.3
 * syntax and hash that, so the key schedule is computed as if a regular
 * TLS 1.3 handshake had run. Hence every serializer takes a
 * ctls_wire_format_t:
 *
 *     CTLS_WIRE_FORMAT_DEFAULT          -> compact cTLS bytes, sent on wire
 *     CTLS_WIRE_FORMAT_TRANSCRIPT_HASH  -> reconstructed TLS 1.3 bytes,
 *                                          fed to the transcript hash only
 *
 * # Data forms
 *
 * Blob-like extensions carry a ctls_data_form_t tag:
 *
 *     CTLS_DATA_FORM_OPAQUE   -> struct aliases a raw byte blob (usually the
 *                                template's predefined data; zero copy)
 *     CTLS_DATA_FORM_PARSED   -> struct holds decoded fields
 *     CTLS_DATA_FORM_SENTINEL -> extension absent
 *
 * Template blobs store extension DATA only — no extension_type and no
 * extension_data length prefix; the serializer prepends those when
 * reconstructing the TLS 1.3 form.
 *
 * # Naming convention
 *
 *     *_create(...)      build extension struct from template / handshake
 *                        state (sender side)
 *     *_deserialize(...) load one extension struct from a source
 *                        (template blob or wire bytes)
 *     *_serialize(...)   write one extension in TLS 1.3 Extension framing
 *                        (transcript reconstruction)
 *     *_to_struct(...)   per-message: rebuild all extension structs on
 *                        receive (mostly from the template, since
 *                        predefined extensions never arrive on the wire)
 *     *_to_wire(...)     per-message: emit all extensions in the chosen
 *                        wire format
 */

#ifndef CTLS_EXTENSIONS_H
#define CTLS_EXTENSIONS_H

#include <stdint.h>
#include "types.h"

/** Width selector for single-value enum extensions (1 or 2 byte payload). */
typedef enum {
    CTLS_HELPER_IS_ONE_BYTE = 0,
    CTLS_HELPER_IS_TWO_BYTE = 1
} ctls_helper_is_one_byte_t;

/** Whose key material a wire field belongs to (e.g. key_share owner). */
typedef enum {
    CTLS_HELPER_ENTITY_OWNERSHIP_CLIENT = 0,
    CTLS_HELPER_ENTITY_OWNERSHIP_SERVER,
} ctls_helper_entity_ownership_t;

/** Pointer + length view over bytes owned elsewhere (template or wire buffer). */
struct ctls_hshk_buffer_block {
    uint8_t *buffer;
    ctls_size_t buffer_length;
};

/**
 * One entry of the server_name extension (RFC 6066, Section 3):
 *
 *     struct {
 *         NameType name_type;     // u8, host_name(0)
 *         opaque HostName<1..2^16-1>;
 *     } ServerName;
 */
struct ctls_extn_server_name_item {
    ctls_extn_host_name_type_t name_type;
    ctls_hshk_buffer_block_t server_name;
};

/**
 * server_name extension (RFC 6066, Section 3):
 *
 *     struct {
 *         ServerName server_name_list<1..2^16-1>
 *     } ServerNameList;
 *
 * OPAQUE form aliases the template blob; PARSED form holds the decoded list.
 */
struct ctls_extn_server_name {
    ctls_data_form_t form;
    uint8_t list_count;
    union {
        ctls_extn_server_name_item_t server_name_list[CTLS_COUNT_SERVER_NAME];
        ctls_hshk_buffer_block_t opaque;
    };
};

/**
 * OCSPStatusRequest body (RFC 6066, Section 8). Both lists are collapsed to
 * single u8 stubs here — the profile never needs real responder IDs or
 * request extensions, so set both to 0.
 */
struct ctls_extn_ocsp_status_request {
    // set these values to 0.
    uint8_t responder_id;
    uint8_t request_extensions;
};

/**
 * status_request extension, parsed form (RFC 6066, Section 8):
 *
 *     struct {
 *         CertificateStatusType status_type;   // u8, ocsp(1)
 *         select (status_type) {
 *             case ocsp: OCSPStatusRequest;
 *         } request;
 *     } CertificateStatusRequest;
 */
struct ctls_extn_certificate_status_request_parsed {
    ctls_extn_certificate_status_type_t certificate_status_type;
    ctls_extn_ocsp_status_request_t ocsp_status_request;
};
struct ctls_extn_certificate_status_request {
    ctls_data_form_t form;
    union {
        ctls_extn_certificate_status_request_parsed_t status_request;
        ctls_hshk_buffer_block_t opaque;
    };
};

/**
 * One ALPN protocol name (RFC 7301, Section 3.1):
 *
 *     opaque ProtocolName<1..2^8-1>;
 */
struct ctls_extn_alpn_protocol_name {
    uint8_t protocol_name_length;
    uint8_t protocol_name[CTLS_SIZE_MAX_ALPN_PROTOCOL_NAME];
};

/**
 * application_layer_protocol_negotiation extension (RFC 7301, Section 3.1):
 *
 *     struct {
 *         ProtocolName protocol_name_list<2..2^16-1>
 *     } ProtocolNameList;
 */
struct ctls_extn_alpn {
    ctls_data_form_t form;
    uint8_t list_count;
    union {
        ctls_extn_alpn_protocol_name_t alpn_list[CTLS_COUNT_ALPN];
        ctls_hshk_buffer_block_t opaque;
    };
};

/**
 * certificate_authorities extension (RFC 8446, Section 4.2.4):
 *
 *     struct {
 *         DistinguishedName authorities<3..2^16-1>;
 *     } CertificateAuthoritiesExtension;
 *
 * Collapsed to a single DistinguishedName — the profile pins one CA.
 */
struct ctls_extn_certificate_authorities {
    ctls_data_form_t form;
    uint8_t distinguished_name_length;
    union {
        ctls_hshk_buffer_block_t opaque;
        uint8_t distinguished_name[CTLS_SIZE_MAX_DISTINGUISHED_NAME];
    };
};

/**
 * SignedCertificateTimestamp, parsed form (RFC 6962, Section 3.2):
 * version + 32-byte log id + u64 timestamp + extensions + signature.
 */
struct ctls_extn_signed_certificate_timestamp_parsed {
    ctls_extn_sct_version_t sct_version;
    uint8_t log_id[CTLS_SIZE_SCT_LOG_ID];
    uint64_t timestamp;
    uint8_t extensions;
    ctls_extn_sct_entry_type_t entry_type;
    ctls_extn_sct_signature_type_t signature_algorithm;
    ctls_hshk_buffer_block_t certificate;
};
struct ctls_extn_signed_certificate_timestamp {
    ctls_data_form_t form;
    union {
        ctls_hshk_buffer_block_t opaque;
        ctls_extn_signed_certificate_timestamp_parsed_t signed_certificate_timestamp;
    };
};

struct ctls_extn_psk_identity {
    uint8_t identity[CTLS_SIZE_PSK_IDENTITY];
    uint8_t identity_length;
    uint32_t obfuscated_ticket_age;
};

struct ctls_extn_offered_psk {
    ctls_extn_psk_identity_t identities[CTLS_COUNT_PSK_IDENTITIES];
    uint8_t binders[CTLS_SIZE_PSK_BINDER];
};

struct ctls_extn_pre_shared_key {
    union {
        ctls_extn_offered_psk_t offered_psk;
        ctls_extn_psk_identity_t psk_identity;
    };
};

struct ctls_extn_early_data {
    uint32_t max_size;
};

#if CTLS_SERVER
struct ctls_extn_oid_filters {
};
#endif
/**
 * All extensions a ClientHello may carry (RFC 8446, Section 4.2, table of
 * permitted messages, column CH). Every member except key_share_entity is
 * filled from the template; key_share_entity points at the freshly generated
 * client ephemeral public key and is the only one sent on the cTLS wire.
 */
struct ctls_extn_client_hello {
    ctls_extn_server_name_t server_name;
    ctls_extn_max_fragment_length_t maximum_fragment_length;
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_supported_group_t supported_groups;
    ctls_extn_signature_algorithm_cert_t signature_algorithm;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_extn_alpn_t alpn;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_padding_t padding;
    ctls_extn_pre_shared_key_t pre_shared_key;
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_psk_key_exchange_mode_t psk_key_exchange_modes;
    ctls_extn_early_data_t early_data;
    ctls_extn_cookie_t cookie;
    ctls_extn_certificate_authorities_t certificate_authorities;
    ctls_extn_post_handshake_auth_t post_handshake_auth;
    ctls_extn_signature_algorithm_cert_t signature_algorithm_cert;
    ctls_extn_key_share_t key_share_entity;
};

/**
 * ServerHello extensions. TLS 1.3 requires supported_versions and key_share
 * here (RFC 8446, Section 4.1.3); supported_versions comes from the
 * template, key_share from the wire.
 */
struct ctls_extn_server_hello {
    ctls_extn_supported_version_t supported_versions;
    ctls_extn_key_share_t key_share_entity;
    ctls_extn_pre_shared_key_t pre_shared_key;
};

/**
 * EncryptedExtensions content (RFC 8446, Section 4.3.1): extensions "not
 * required to establish the cryptographic parameters". All predefined by the
 * template in cTLS — nothing arrives on the wire.
 */
struct ctls_extn_encrypted_extensions {
    ctls_extn_server_name_t server_name;
    ctls_extn_max_fragment_length_t maximum_fragment_length;
    ctls_extn_supported_group_t supported_groups;
    ctls_extn_heartbeat_mode_t heartbeat_mode;
    ctls_extn_alpn_t alpn;
    ctls_extn_certificate_type_t client_certificate_type;
    ctls_extn_certificate_type_t server_certificate_type;
    ctls_extn_early_data_t early_data;
};

/**
 * CertificateRequest extensions (RFC 8446, Section 4.3.2). The
 * signature_algorithms extension is mandatory there ("MUST be specified");
 * the rest are optional and template-driven.
 */
struct ctls_extn_certificate_request {
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_signature_algorithm_cert_t signature_algorithm;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
    ctls_extn_certificate_authorities_t certificate_authorities;
    ctls_extn_signature_algorithm_cert_t signature_algorithm_cert;
};

/**
 * Per-CertificateEntry extensions (RFC 8446, Section 4.4.2): "Valid
 * extensions for server certificates at present include the OCSP Status
 * extension [RFC6066] and the SignedCertificateTimestamp extension
 * [RFC6962]".
 */
struct ctls_extn_certificate {
    ctls_extn_certificate_status_request_t certificate_status_request;
    ctls_extn_signed_certificate_timestamp_t signed_certificate_timestamp;
};

struct ctls_extn_new_session_ticket {
    ctls_extn_early_data_t early_data;
};

/**
 * Copy a single 1- or 2-byte enum value out of a template field into an
 * extension struct member. No wire framing involved — templates store bare
 * values.
 */
ctls_status_t ctls_extn_enum_deserialize(void const *source,
                                         void *destination,
                                         ctls_helper_is_one_byte_t isOneByte);

/**
 * Write a single-value enum extension in TLS 1.3 Extension framing:
 * extension_type(u16) | extension_data_length(u16, = 1 or 2) | value.
 * Used for transcript reconstruction. The TLS 1.3 list wrappers (e.g.
 * NamedGroupList) are dropped: the profile pins exactly one value.
 */
ctls_status_t ctls_extn_enum_serialize(uint8_t *buffer,
                                       ctls_size_t *offset,
                                       ctls_extn_type_t extn_type,
                                       ctls_helper_is_one_byte_t isOneByte,
                                       uint16_t value);

/**
 * Check whether the template predefines extension extn_type for handshake
 * message hsmg_type. "Initialized" = present in that message's
 * predefined_extensions (non-sentinel / non-empty). This is the gate that
 * decides whether an extension exists on this connection at all.
 */
ctls_status_t ctls_extn_is_initialized(ctls_extn_type_t extn_type,
                                       ctls_hsmg_type_t hsmg_type,
                                       uint8_t *is_initialized);

/**
 * Write an opaque blob with TLS 1.3 framing:
 * [extension_type(u16) unless CTLS_EXTN_TYPE_SENTINEL] |
 * extension_data_length(u16) | raw bytes.
 * Pass SENTINEL when the caller already wrote the type itself.
 */
ctls_status_t ctls_extn_opaque_serialize(uint8_t *destination_buffer,
                                         ctls_size_t *destination_offset,
                                         uint8_t const *source_buffer,
                                         ctls_size_t source_length,
                                         ctls_extn_type_t extension_type);

/**
 * Load server_name (RFC 6066, Section 3) from a source blob.
 * OPAQUE: alias the blob (zero copy). PARSED: decode
 * server_name_list_length(u16) then entries of
 * name_type(u8) | host_name_length(u16) | host_name bytes.
 */
ctls_status_t ctls_extn_server_name_deserialize(uint8_t *buffer,
                                                ctls_size_t const *buffer_length,
                                                ctls_data_form_t form,
                                                ctls_extn_server_name_t *server_name);
/** Write server_name in TLS 1.3 Extension framing (transcript form). */
ctls_status_t ctls_extn_server_name_serialize(uint8_t *buffer,
                                              ctls_size_t *offset,
                                              ctls_extn_server_name_t const *server_name);

/**
 * max_fragment_length (RFC 6066, Section 4):
 * "enum{ 2^9(1), 2^10(2), 2^11(3), 2^12(4), (255) } MaxFragmentLength;"
 * Single byte; copied from / framed via the enum helpers.
 */
ctls_status_t ctls_extn_max_fragment_length_deserialize(
    ctls_extn_max_fragment_length_t const *source,
    ctls_extn_max_fragment_length_t *max_fragment_length);
ctls_status_t ctls_extn_max_fragment_length_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_max_fragment_length_t const *max_fragment_length);

/**
 * Build status_request from handshake state: when the peer requested
 * certificate status, point at the canned OCSP response DER for the given
 * entity; otherwise mark the extension absent (form = SENTINEL).
 */
ctls_status_t ctls_extn_certificate_status_request_create(
    ctls_extn_certificate_status_request_t *certificate_status_request,
    ctls_entity_t entity);
/**
 * Load status_request (RFC 6066, Section 8). OPAQUE: alias blob.
 * PARSED: decode CertificateStatusRequest — only status_type ocsp(1) is
 * accepted; responder list and request extensions are read as 1-byte stubs.
 */
ctls_status_t ctls_extn_certificate_status_request_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_certificate_status_request_t *certificate_status_request);
/** Write status_request in TLS 1.3 Extension framing (transcript form). */
ctls_status_t ctls_extn_certificate_status_request_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_status_request_t const *certificate_status_request);

/**
 * supported_groups (RFC 8446, Section 4.2.7):
 * "NamedGroup named_group_list<2..2^16-1>;" — collapsed to the single u16
 * NamedGroup the template pins.
 */
ctls_status_t ctls_extn_supported_groups_deserialize(
    ctls_extn_supported_group_t const *source,
    ctls_extn_supported_group_t *supported_group);
ctls_status_t ctls_extn_supported_groups_serialize(uint8_t *buffer,
                                                   ctls_size_t *offset,
                                                   ctls_extn_supported_group_t const *
                                                   supported_groups);

/**
 * signature_algorithms (RFC 8446, Section 4.2.3):
 * "SignatureScheme supported_signature_algorithms<2..2^16-2>;" — collapsed
 * to the single u16 SignatureScheme the template pins.
 */
ctls_status_t ctls_extn_signature_algorithm_deserialize(
    ctls_extn_signature_algorithm_t const *source,
    ctls_extn_signature_algorithm_t *signature_algorithm);
ctls_status_t ctls_extn_signature_algorithm_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm);

/**
 * signature_algorithms_cert (RFC 8446, Section 4.2.3): same encoding as
 * signature_algorithms, applies to signatures in certificates.
 */
ctls_status_t ctls_extn_signature_algorithm_cert_deserialize(
    ctls_extn_signature_algorithm_t const *source,
    ctls_extn_signature_algorithm_t *signature_algorithm_cert);
ctls_status_t ctls_extn_signature_algorithm_cert_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signature_algorithm_t const *signature_algorithm_cert);

/**
 * heartbeat (RFC 6520, Section 2): single HeartbeatMode byte,
 * peer_allowed_to_send(1) or peer_not_allowed_to_send(2).
 */
ctls_status_t ctls_extn_heartbeat_mode_deserialize(
    ctls_extn_heartbeat_mode_t const *source,
    ctls_extn_heartbeat_mode_t *heartbeat_mode);
ctls_status_t ctls_extn_heartbeat_mode_serialize(uint8_t *buffer,
                                                 ctls_size_t *offset,
                                                 ctls_extn_heartbeat_mode_t const *
                                                 heartbeat_mode);

/**
 * Load ALPN (RFC 7301, Section 3.1). OPAQUE: alias blob. PARSED: decode
 * protocol_name_list_length(u16) then entries of
 * protocol_name_length(u8) | protocol_name bytes.
 */
ctls_status_t ctls_extn_alpn_deserialize(uint8_t *buffer,
                                         ctls_size_t const *buffer_length,
                                         ctls_data_form_t form,
                                         ctls_extn_alpn_t *alpn);
/** Write ALPN in TLS 1.3 Extension framing (transcript form). */
ctls_status_t ctls_extn_alpn_serialize(uint8_t *buffer,
                                       ctls_size_t *offset,
                                       ctls_extn_alpn_t const *alpn);

/**
 * Build signed_certificate_timestamp from handshake state: point at the
 * canned SCT DER for the given entity, or mark absent.
 */
ctls_status_t ctls_extn_signed_certificate_timestamp_create(
    ctls_extn_signed_certificate_timestamp_t *signed_certificate_timestamp,
    ctls_entity_t entity);
/**
 * Load SCT (RFC 6962, Section 3.2). OPAQUE: alias blob. PARSED: decode
 * sct_version(u8) | log_id(32B) | timestamp(u64) | extensions(u8 stub) |
 * signature_algorithm(u16) | certificate_length(u16) | certificate bytes.
 */
ctls_status_t ctls_extn_signed_certificate_timestamp_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_signed_certificate_timestamp_t *signed_certificate_timestamp);
/** Write SCT in TLS 1.3 Extension framing (transcript form). */
ctls_status_t ctls_extn_signed_certificate_timestamp_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_signed_certificate_timestamp_t const *signed_certificate_timestamp);

/**
 * client_certificate_type (RFC 7250): single CertificateType byte the
 * template pins (X.509(0) or RawPublicKey(2)).
 */
ctls_status_t ctls_extn_client_certificate_type_deserialize(
    ctls_extn_client_certificate_type_t const *source,
    ctls_extn_client_certificate_type_t *client_certificate_type);
ctls_status_t ctls_extn_client_certificate_type_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_client_certificate_type_t const *client_certificate_type);

/** server_certificate_type (RFC 7250): same encoding as client variant. */
ctls_status_t ctls_extn_server_certificate_type_deserialize(
    ctls_extn_server_certificate_type_t const *source,
    ctls_extn_server_certificate_type_t *server_certificate_type);
ctls_status_t ctls_extn_server_certificate_type_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_server_certificate_type_t const *server_certificate_type);

/**
 * supported_versions (RFC 8446, Section 4.2.1). TLS 1.3 sends a version
 * list in CH and a single selected_version in SH; here the template pins one
 * ProtocolVersion (0x0304), so both collapse to a single u16.
 */
ctls_status_t ctls_extn_supported_versions_deserialize(
    ctls_extn_supported_version_t const *source,
    ctls_extn_supported_version_t *supported_versions);
ctls_status_t ctls_extn_supported_versions_serialize(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_extn_supported_version_t const *
                                                     supported_versions);

/**
 * psk_key_exchange_modes (RFC 8446, Section 4.2.9):
 * "PskKeyExchangeMode ke_modes<1..255>;" — collapsed to the single u8 mode
 * the template pins.
 */
ctls_status_t ctls_extn_psk_key_exchange_modes_deserialize(
    ctls_extn_psk_key_exchange_mode_t const *source,
    ctls_extn_psk_key_exchange_mode_t *psk_key_exchange_modes);
ctls_status_t ctls_extn_psk_key_exchange_modes_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_psk_key_exchange_mode_t const *psk_key_exchange_modes);

/**
 * Load certificate_authorities (RFC 8446, Section 4.2.4). OPAQUE: alias
 * blob. PARSED: decode distinguished_name_length(u16) | DN bytes (single
 * DistinguishedName, list collapsed).
 */
ctls_status_t ctls_extn_certificate_authorities_deserialize(
    uint8_t *buffer,
    ctls_size_t const *buffer_length,
    ctls_data_form_t form,
    ctls_extn_certificate_authorities_t *certificate_authorities);
/** Write certificate_authorities in TLS 1.3 Extension framing. */
ctls_status_t ctls_extn_certificate_authorities_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_certificate_authorities_t const *certificate_authorities);

/**
 * post_handshake_auth (RFC 8446, Section 4.2.6): "The 'extension_data'
 * field ... is zero length." Deserialize copies the template flag;
 * serialize writes extension_type(u16) | length(u16)=0, or nothing when the
 * flag is unset.
 */
ctls_status_t ctls_extn_post_handshake_auth_deserialize(
    ctls_extn_post_handshake_auth_t const *source,
    ctls_extn_post_handshake_auth_t *post_handshake_auth);
ctls_status_t ctls_extn_post_handshake_auth_serialize(
    uint8_t *buffer,
    ctls_size_t *offset,
    ctls_extn_post_handshake_auth_t const *post_handshake_auth);

/**
 * Read a key_share (RFC 8446, Section 4.2.8) from the wire. The TLS 1.3
 * KeyShareEntry is { NamedGroup group; opaque key_exchange<1..2^16-1>; };
 * in cTLS group and length are fixed by the template, so only the raw
 * CTLS_SIZE_KEY_SHARE key bytes appear on the wire. Bytes are copied into
 * hshk_data's client or server ephemeral key per entity_ownership and
 * *key_share is pointed at that storage.
 */
ctls_status_t ctls_extn_key_share_deserialize(uint8_t const *buffer,
                                              ctls_size_t *offset,
                                              ctls_helper_entity_ownership_t
                                              entity_ownership,
                                              ctls_extn_key_share_t *key_share);
/**
 * Write a key_share. DEFAULT: key_exchange_length(u16) | key bytes.
 * TRANSCRIPT_HASH: additionally prefixed with extension_type(u16) to match
 * TLS 1.3 framing.
 */
ctls_status_t ctls_extn_key_share_serialize(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_wire_format_t wire_format,
                                            ctls_extn_key_share_t key_share);

/**
 * Build the full ClientHello extension set: for every extension the template
 * predefines, load it from the template blob/field; if key_share is
 * expected, generate the client ephemeral key pair and reference its public
 * half.
 */
ctls_status_t ctls_extn_client_hello_create(
    ctls_extn_client_hello_t *client_hello_extensions);
ctls_status_t ctls_extn_client_hello_to_struct();
/**
 * Emit ClientHello extensions.
 * DEFAULT (cTLS wire): only dynamic data — the key_share bytes; everything
 * else is reconstructed by the peer from its template.
 * TRANSCRIPT_HASH: every present extension in TLS 1.3 Extension framing,
 * in the order of the ctls_extn_client_hello struct, key_share last.
 */
ctls_status_t ctls_extn_client_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_extn_client_hello_t const *
                                             client_hello_extensions,
                                             ctls_wire_format_t wire_format);


ctls_status_t ctls_extn_server_hello_create(void);
/**
 * Rebuild ServerHello extensions on receive: supported_versions from the
 * template (never on wire), key_share from the wire bytes at *offset.
 */
ctls_status_t ctls_extn_server_hello_to_struct(
    ctls_extn_server_hello_t *server_hello_extensions,
    uint8_t const *buffer,
    ctls_size_t *offset);
/**
 * Emit ServerHello extensions. TRANSCRIPT_HASH: supported_versions then
 * key_share in TLS 1.3 framing. DEFAULT: not implemented (client-only
 * build does not send ServerHello).
 */
ctls_status_t ctls_extn_server_hello_to_wire(uint8_t *buffer,
                                             ctls_size_t *offset,
                                             ctls_extn_server_hello_t const *
                                             server_hello_extensions,
                                             ctls_wire_format_t wire_format);


ctls_status_t ctls_extn_encrypted_extensions_create(
    ctls_hsmg_encrypted_extensions_t *encrypted_extensions);
/**
 * Rebuild EncryptedExtensions content purely from the template — in cTLS
 * none of these extensions travel on the wire. Fails if the template
 * expects dynamic extensions here (none are defined for EE).
 */
ctls_status_t ctls_extn_encrypted_extensions_to_struct(
    ctls_extn_encrypted_extensions_t *encrypted_extensions);
/** Emit EncryptedExtensions extensions (TRANSCRIPT_HASH reconstruction). */
ctls_status_t ctls_extn_encrypted_extensions_to_wire(uint8_t *buffer,
                                                     ctls_size_t *offset,
                                                     ctls_extn_encrypted_extensions_t
                                                     const *encrypted_extensions,
                                                     ctls_wire_format_t wire_format);

ctls_status_t ctls_extn_certificate_request_create(void);
/** Rebuild CertificateRequest extensions from the template. */
ctls_status_t ctls_extn_certificate_request_to_struct(
    ctls_extn_certificate_request_t *certificate_request_extensions);
/** Emit CertificateRequest extensions (TRANSCRIPT_HASH reconstruction). */
ctls_status_t ctls_extn_certificate_request_to_wire(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_extn_certificate_request_t const
                                                    *certificate_request,
                                                    ctls_wire_format_t wire_format);

/**
 * Build per-CertificateEntry extensions from handshake state: OCSP status
 * response and/or SCT, only when the peer requested them during the
 * handshake (RFC 8446, Section 4.4.2 allows only these two).
 */
ctls_status_t ctls_extn_certificate_create(ctls_extn_certificate_t *ctls_certificate,
                                           ctls_entity_t entity);
/** Rebuild per-CertificateEntry extensions from the template. */
ctls_status_t ctls_extn_certificate_to_struct(
    ctls_extn_certificate_t *certificate_extensions);
/** Emit per-CertificateEntry extensions (TRANSCRIPT_HASH reconstruction). */
ctls_status_t ctls_extn_certificate_to_wire(uint8_t *buffer,
                                            ctls_size_t *offset,
                                            ctls_extn_certificate_t const *
                                            certificate_extensions,
                                            ctls_wire_format_t wire_format);


#endif
