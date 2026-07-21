// Created by Sanjay Kumar Kumaravelan on 19/04/26.

/**
 * @file crypto.h
 * @brief Crypto layer over PSA Crypto: transcript hash, key schedule,
 *        record AEAD, signatures, Finished MAC.
 *
 * References:
 *   - RFC 8446 §7.1 — key schedule (HKDF-Extract / HKDF-Expand-Label)
 *   - RFC 8446 §5.2/§5.3 — AEAD record protection and per-record nonce
 *   - RFC 8446 §4.4.3 — CertificateVerify signed content
 *   - RFC 8446 §4.4.4 — Finished verify_data
 *   - RFC 5869 — HKDF
 *   - draft-ietf-tls-ctls — cTLS replaces the "tls13 " HKDF label prefix;
 *     this implementation uses CTLS_LABEL_PREFIX, "Sctls " or "Dctls "
 *     depending on transport reliability (see ctls_context_string_build)
 *
 * # Key schedule (RFC 8446 §7.1, PSK-less profile)
 *
 *     early_secret      = HKDF-Extract(salt=0, ikm=0)
 *     derived_secret    = Expand-Label(early_secret, "derived", H(""), 32)
 *     handshake_secret  = HKDF-Extract(derived_secret, ECDHE shared secret)
 *     c/s hs traffic    = Expand-Label(handshake_secret, "c|s hs traffic",
 *                                      Transcript-Hash, 32)
 *     key               = Expand-Label(traffic_secret, "key", "", 16)
 *     iv                = Expand-Label(traffic_secret, "iv",  "", 12)
 *
 * Driven start-to-finish by ctls_key_schedule(), which also bumps the
 * epoch to 2 (handshake keys, RFC 9147 §6.1 numbering).
 *
 * # Transcript hash
 *
 * Running hash over the handshake messages in reconstructed TLS 1.3 form
 * (TRANSCRIPT_HASH wire format — see extensions.h). The canonical template
 * bytes are hashed first, binding the profile into the key schedule.
 * Intermediate values are read via transcript_snapshot (clone + finish) so
 * the running operator survives.
 *
 * All primitives run through PSA Crypto (Mbed TLS backend); keys live as
 * PSA key handles and are destroyed after each use.
 */

#ifndef CTLS_CRYPTO_H
#define CTLS_CRYPTO_H

#include <psa/crypto.h>
#include "types.h"

/*
 * cTLS HKDF label prefix (draft-ietf-tls-ctls §2.3.2), replacing RFC 8446's
 * "tls13 ": "Sctls " for Stream cTLS (reliable transport), "Dctls " for
 * Datagram cTLS (unreliable transport) — see CTLS_STREAM /
 * CTLS_DATAGRAM in config.h.
 */
#if CTLS_STREAM
#define CTLS_LABEL_PREFIX "Sctls "
#elif CTLS_DATAGRAM
#define CTLS_LABEL_PREFIX "Dctls "
#endif

#define CTLS_SIZE_NONCE 12U
#define CTLS_SIZE_TRANSCRIPT_HASH 32U

#define CTLS_CHECK_NULL_KEY_ID(p) \
    do { if ((p) == NULL) return CTLS_STATUS_NULL_PTR; } while (0)

/** PSA key attribute profile to apply; passed to ctls_key_attributes_set. */
typedef enum {
    CTLS_KEY_USAGE_EPHEMERAL_KEY_PAIR_GENERATE = 0,
    CTLS_KEY_USAGE_EPHEMERAL_PUBLIC_KEY_EXPORT,
    CTLS_KEY_USAGE_HKDF_EXTRACT,
    CTLS_KEY_USAGE_HKDF_EXPAND,
    CTLS_KEY_USAGE_AEAD_ENCRYPT_OR_DECRYPT,
    CTLS_KEY_USAGE_SIGN_MESSAGE,
    CTLS_KEY_USAGE_VERIFY_SIGNATURE,
    CTLS_KEY_USAGE_HMAC,
} ctls_key_usage_t;

/** Which HkdfLabel / signing context ctls_context_string_build emits. */
typedef enum {
    CTLS_KEY_TYPE_EARLY_SECRET = 0,
    CTLS_KEY_TYPE_BINDER_KEY,
    CTLS_KEY_TYPE_CLIENT_EARLY_KEY,
    CTLS_KEY_TYPE_EXPORTER_MASTER_SECRET,
    CTLS_KEY_TYPE_DERIVED_SECRET,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_SECRET,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_WRITE_KEYS,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_IV_KEY,
    CTLS_KEY_TYPE_SIGNED_BYTES,
    CTLS_KEY_TYPE_FINISHED_KEY,
    CTLS_KEY_TYPE_APPLICATION_TRAFFIC_SECRET,
    CTLS_KEY_TYPE_APPLICATION_TRAFFIC_WRITE_KEYS,
    CTLS_KEY_TYPE_APPLICATION_TRAFFIC_IV_KEY,
} ctls_key_type_t;

/** PSA state owned by the connection: hash/derivation operators, key ids. */
struct ctls_crypto {
    psa_algorithm_t hash_algorithm;
    psa_hash_operation_t transcript_hash_operator;
    psa_ecc_family_t ecdhe_key_pair_type;
    psa_key_derivation_operation_t key_schedule_operator;
    psa_key_id_t self_ephemeral_key_pair; // own ECDHE key pair (client or server)
    psa_key_id_t peer_public_ephemeral_key; // peer's ECDHE public key from KeyShare
    psa_key_id_t shared_ephemeral_secret; // ECDH output; IKM for handshake_secret Extract
    psa_key_id_t early_secret; // HKDF-Extract(0, 0) — no-PSK baseline
    psa_key_id_t derived_secret; // Expand-Label(early_secret, "derived", H(""))
    psa_key_id_t handshake_secret; // HKDF-Extract(derived_secret, ECDHE)
    psa_key_id_t client_handshake_traffic_secret;
    psa_key_id_t client_handshake_write_key; // Expand-Label(c_hs_traffic, "key", "", 16)
    psa_key_id_t client_handshake_iv_key; // Expand-Label(c_hs_traffic, "iv",  "", 12)
    psa_key_id_t server_handshake_traffic_secret;
    psa_key_id_t server_handshake_write_key; // Expand-Label(s_hs_traffic, "key", "", 16)
    psa_key_id_t server_handshake_iv_key; // Expand-Label(s_hs_traffic, "iv",  "", 12)
    psa_key_id_t self_certificate_key_pair;
    // own Ed25519 private key for CertificateVerify
    psa_key_id_t peer_certificate_public_key; // peer's Ed25519 public key for verify
    psa_key_id_t client_finished_key; // Expand-Label(c_hs_traffic, "finished", "", 32)
    psa_key_id_t server_finished_key; // Expand-Label(s_hs_traffic, "finished", "", 32)
    psa_key_id_t master_secret;
    psa_key_id_t client_application_traffic_secret;
    psa_key_id_t server_application_traffic_secret;
    psa_key_id_t exporter_master_secret;
    psa_key_id_t client_application_write_key;
    psa_key_id_t server_application_write_key;
    psa_key_id_t client_application_iv_key;
    psa_key_id_t server_application_iv_key;
};

/**
 * @brief Map a psa_status_t onto the closest ctls_status_t.
 * @param status  PSA error code to translate.
 * @return The matching CTLS_STATUS_CRYPTO_* code, or CTLS_STATUS_CRYPTO_UNKNOWN.
 */
ctls_status_t ctls_psa_error_map(psa_status_t status);

/**
 * @brief One-time PSA crypto setup: init, algorithm selection, transcript hash start.
 *
 * Calls psa_crypto_init, derives hash algorithm and ECC family from the
 * template's cipher suite, starts the running transcript hash and feeds
 * the canonical template bytes as its first input.
 *
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_INIT_FAILED on failure.
 */
ctls_status_t ctls_crypto_init();

/**
 * @brief Select the PSA hash algorithm for the given cipher suite.
 *
 * Sets crypto->hash_algorithm to the HKDF hash implied by the suite
 * (e.g. TLS_AES_128_GCM_SHA256 → PSA_ALG_SHA_256, RFC 8446 §B.4).
 *
 * @param crypto        Crypto state to update.
 * @param cipher_suite  Cipher suite from the active template.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_UNSUPPORTED_CIPHER_SUITE.
 */
ctls_status_t ctls_psa_hash_algorithm_set(ctls_crypto_t *crypto,
                                          ctls_cipher_suite_t cipher_suite);

/**
 * @brief Return the key size in bits for a PSA algorithm.
 *
 * Maps AES-128-GCM → 128, HMAC-SHA-256 → 256, etc. Used by
 * ctls_key_attributes_set to configure key sizes for derived keys.
 *
 * @param algorithm  PSA algorithm to query.
 * @param key_bits   Output: key size in bits.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_KEY_BITS_UNKNOWN_ALG.
 */
ctls_status_t ctls_key_bits_get(psa_algorithm_t const *algorithm, ctls_size_t *key_bits);

/**
 * @brief Select the PSA ECC/DH family for the given NamedGroup.
 *
 * Sets crypto->ecdhe_key_pair_type (e.g. x25519 → PSA_ECC_FAMILY_MONTGOMERY).
 * Used during key-pair generation for the ephemeral ECDHE key share.
 *
 * @param crypto          Crypto state to update.
 * @param dhe_group_type  NamedGroup from the active template.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_UNSUPPORTED_DHE_GROUP.
 */
ctls_status_t ctls_psa_ecc_family_set(ctls_crypto_t *crypto,
                                      ctls_dhe_group_t dhe_group_type);

/**
 * @brief Start the running transcript hash and feed canonical template bytes.
 *
 * Initializes the PSA hash operator on crypto->transcript_hash_operator,
 * calls ctls_template_to_wire to serialize the template, and absorbs
 * those bytes as the first hash input. Both peers must share the same
 * template for the transcript to agree.
 *
 * @param crypto          Crypto state whose transcript_hash_operator to initialize.
 * @param transcript_hash Output buffer (CTLS_SIZE_TRANSCRIPT_HASH bytes) for the
 *                        initial snapshot (may be NULL if not needed immediately).
 * @param template        Active cTLS template to serialize and hash.
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_HASH_* code on failure.
 */
ctls_status_t ctls_transcript_hash_init(ctls_crypto_t *crypto,
                                        uint8_t *transcript_hash,
                                        ctls_template_t const *template);

/**
 * @brief Finish the current transcript hash into a buffer without aborting the operator.
 *
 * Clones hash_operator, finishes the clone, and writes CTLS_SIZE_TRANSCRIPT_HASH
 * bytes to transcript_hash. The running operator is unaffected.
 *
 * @param hash_operator   Running PSA hash operation to snapshot.
 * @param transcript_hash Output: CTLS_SIZE_TRANSCRIPT_HASH-byte hash digest.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HASH_SNAP_* on clone/finish failure.
 */
ctls_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                             uint8_t *transcript_hash);

/**
 * @brief Serialize a record in TRANSCRIPT_HASH wire format and absorb it.
 *
 * Calls the record's *_to_wire function with CTLS_WIRE_FORMAT_TRANSCRIPT_HASH
 * (reconstructed TLS 1.3 bytes), then feeds the output into the running
 * transcript hash operator. Called once per handshake message from the driver.
 *
 * @param record  Deserialized or freshly built record to hash.
 * @param type    Handshake message type (selects the *_to_wire dispatch).
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_HASH_* / record layer error.
 */
ctls_status_t ctls_transcript_hash_update(ctls_record_t const *record,
                                          ctls_hsmg_type_t type);

/**
 * @brief Read the current transcript hash without consuming the running operator.
 *
 * Clones hash_operator (PSA clone), finishes the clone into buffer, and
 * destroys the clone — the original operator continues accumulating input.
 *
 * @param hash_operator  Running PSA hash operator to snapshot (read-only).
 * @param buffer         Output: CTLS_SIZE_TRANSCRIPT_HASH bytes of digest.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HASH_SNAP_* on failure.
 */
ctls_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                  uint8_t *buffer);

/**
 * @brief Initialize the HKDF derivation operator and select ECC family.
 *
 * Calls ctls_key_schedule_operator_reset (aborts any in-progress derivation)
 * and ctls_psa_ecc_family_set for the given NamedGroup.
 *
 * @param crypto           Crypto state to initialize.
 * @param ecdhe_group_type NamedGroup from the active template.
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_* error.
 */
ctls_status_t ctls_hkdf_init(ctls_crypto_t *crypto, ctls_dhe_group_t ecdhe_group_type);

/**
 * @brief Abort and reinitialize the PSA key derivation operator.
 *
 * Required between consecutive HKDF Extract/Expand steps because PSA
 * derivation operations are single-use. Calls psa_key_derivation_abort
 * and re-initializes to PSA_KEY_DERIVATION_OPERATION_INIT.
 *
 * @param crypto  Crypto state whose key_schedule_operator to reset.
 * @return CTLS_STATUS_SUCCESS always (abort never fails by PSA spec).
 */
ctls_status_t ctls_key_schedule_operator_reset(ctls_crypto_t *crypto);

/**
 * @brief Import raw peer public key bytes as a PSA key-agreement key.
 *
 * Imports the X25519 (or other NamedGroup) public point received in the
 * peer's KeyShare extension into a transient PSA key handle for use in
 * psa_raw_key_agreement.
 *
 * @param buffer                Peer's raw public key bytes.
 * @param buffer_length         Length of buffer in bytes (e.g. 32 for x25519).
 * @param ephemeral_public_key  Output: PSA key handle for the imported public key.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_EPHEM_PUB_KEY_IMPORT_FAILED.
 */
ctls_status_t ctls_ephemeral_public_key_import(uint8_t const *buffer,
                                               ctls_size_t buffer_length,
                                               psa_key_id_t *ephemeral_public_key);

/**
 * @brief Export the public half of an ephemeral key pair to raw bytes.
 *
 * Extracts the public point from ephemeral_key_pair_id (the locally generated
 * ECDHE key pair) and writes it to buffer for inclusion in a KeyShare entry.
 *
 * @param ephemeral_key_pair_id  PSA key handle of the local ECDHE key pair.
 * @param buffer                 Output buffer for the raw public key bytes.
 * @param buffer_length          Size of buffer in bytes.
 * @param buffer_bytes_written   Output: number of bytes written.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_EPHEM_KEY_EXPORT_FAILED.
 */
ctls_status_t ctls_ephemeral_public_key_export(psa_key_id_t const *ephemeral_key_pair_id,
                                               uint8_t *buffer,
                                               ctls_size_t buffer_length,
                                               ctls_size_t *buffer_bytes_written);

/**
 * @brief Generate an ECDHE key pair into a transient PSA key handle.
 *
 * Uses the ECC family already set in crypto->ecdhe_key_pair_type. The public
 * half is exported separately via ctls_ephemeral_public_key_export for the
 * KeyShare extension.
 *
 * @param ephemeral_key_pair_id  Output: PSA key handle for the generated key pair.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_KEY_GEN_FAILED.
 */
ctls_status_t ctls_ephemeral_key_pair_generate(psa_key_id_t *ephemeral_key_pair_id);

/**
 * @brief Generate random bytes from the PSA DRBG.
 *
 * Used for Hello random fields (RFC 8446 §4.1.2). Calls psa_generate_random.
 *
 * @param buffer        Output buffer; must be at least random_size bytes.
 * @param bytes_written Output: number of random bytes written (equals random_size).
 * @param random_size   Number of random bytes to generate.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_RANDOM_FAILED.
 */
ctls_status_t ctls_random_generate(uint8_t *buffer,
                                   ctls_size_t *bytes_written,
                                   uint8_t random_size);

/**
 * @brief Run the full handshake key schedule (early_secret → handshake keys + IVs).
 *
 * Drives the sequence shown in the file-header diagram: early_secret,
 * derived_secret, shared_ephemeral_secret, handshake_secret, handshake
 * traffic secrets, write keys and IVs for both entities, then bumps the
 * epoch to 2. Call after ServerHello (needs the server key share + transcript).
 *
 * @return CTLS_STATUS_SUCCESS, or the first CTLS_STATUS_CRYPTO_* error.
 */
ctls_status_t ctls_key_schedule();

/**
 * @brief Set PSA key attributes for the given derivation or usage context.
 *
 * Configures type, usage flags, algorithm, and key bits on key_attribute
 * based on key_usage. Called internally before importing or deriving each key.
 *
 * @param key_usage      Which operation these attributes are for (one of CTLS_KEY_USAGE_*).
 * @param key_attribute  PSA key attributes struct to populate.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_KEY_ATTR_* on unsupported usage.
 */
ctls_status_t ctls_key_attributes_set(ctls_key_usage_t key_usage,
                                      psa_key_attributes_t *key_attribute);

/**
 * @brief Build HkdfLabel or CertificateVerify signing content bytes.
 *
 * For key derivation types: writes an HkdfLabel per RFC 8446 §7.1:
 *   length(u16) | label_len(u8) | CTLS_LABEL_PREFIX "<label>" | context_len(u8) | context.
 * For CTLS_KEY_TYPE_SIGNED_BYTES: writes §4.4.3 content:
 *   64 × 0x20 | context string | 0x00 | Transcript-Hash.
 * CTLS_LABEL_PREFIX replaces TLS 1.3's "tls13 " per the cTLS draft.
 *
 * @param buffer    Output buffer; must be large enough for the label (caller ensures).
 * @param offset    Current write position in buffer; advanced past written bytes.
 * @param entity    CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects c/s label variant).
 * @param key_type  Which label or signing context to build (one of CTLS_KEY_TYPE_*).
 * @param limit     Capacity of buffer (caller's real array size, e.g. sizeof(info)) —
 *                  every internal write is bounds-checked against this.
 * @return CTLS_STATUS_SUCCESS, CTLS_STATUS_CRYPTO_CONTEXT_STR_UNKNOWN_KEY_TYPE, or
 *         CTLS_STATUS_BOUNDS_EXCEEDED if a write would exceed limit.
 */
ctls_status_t ctls_context_string_build(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        ctls_entity_t entity,
                                        ctls_key_type_t key_type,
                                        ctls_size_t limit);

/* ------------------------------------------------------------------ */
/* Key schedule step functions (file-header diagram order)            */
/* ------------------------------------------------------------------ */

/**
 * @brief HKDF-Extract(salt=0, ikm=0) → early_secret.
 *
 * Baseline no-PSK early secret (RFC 8446 §7.1). Result stored in
 * crypto->early_secret.
 *
 * @param crypto  Crypto state; early_secret field is set on success.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_EARLY_SECRET_EXTRACT_FAILED.
 */
ctls_status_t ctls_early_secret_generate(ctls_crypto_t *crypto);

/**
 * @brief Expand-Label(salt, "derived", H(""), 32) → derived_secret.
 *
 * RFC 8446 §7.1's key schedule computes this Derive-Secret step twice, from
 * two different salts — once from early_secret (salting handshake_secret),
 * once from handshake_secret (salting master_secret) — so salt is a
 * parameter, not hardcoded. Result always overwrites crypto->derived_secret;
 * it's a transient value with no use after whichever HKDF-Extract consumes
 * it next.
 *
 * @param crypto  Crypto state; derived_secret field is set on success.
 * @param salt    early_secret (first call, in ctls_key_schedule) or
 *                handshake_secret (second call, in ctls_master_secret_generate).
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_HKDF_EXPAND_* error.
 */
ctls_status_t ctls_derived_secret_generate(ctls_crypto_t *crypto, psa_key_id_t const *salt);

/**
 * @brief psa_raw_key_agreement(ECDH, self_key_pair, peer_public_key) → shared_ephemeral_secret.
 *
 * Performs the ECDH operation using the locally generated key pair and the
 * peer's imported public key. Result stored in crypto->shared_ephemeral_secret
 * and used as IKM in ctls_handshake_secret_generate.
 *
 * @param crypto  Crypto state; shared_ephemeral_secret is set on success.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_ECDH_FAILED.
 */
ctls_status_t ctls_shared_ephemeral_secret_generate(ctls_crypto_t *crypto);

/**
 * @brief HKDF-Extract(derived_secret, shared_ephemeral_secret) → handshake_secret.
 *
 * Result stored in crypto->handshake_secret.
 *
 * @param crypto  Crypto state; handshake_secret is set on success.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HKDF_EXTRACT_FAILED.
 */
ctls_status_t ctls_handshake_secret_generate(ctls_crypto_t *crypto);

/**
 * @brief Expand-Label(handshake_secret, "c|s hs traffic", Transcript-Hash, 32).
 *
 * Derives the client or server handshake traffic secret and stores it in
 * crypto->client_handshake_traffic_secret or server_handshake_traffic_secret.
 *
 * @param crypto  Crypto state; c/s_handshake_traffic_secret is set on success.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HS_TRAFFIC_SECRET_EXPAND_FAILED.
 */
ctls_status_t ctls_handshake_traffic_secret_generate(ctls_crypto_t *crypto,
                                                     ctls_entity_t entity);

/**
 * @brief Expand-Label(hs_traffic_secret, "key", "", 16) → AES-128-GCM write key.
 *
 * Derives the handshake write key for the given entity and stores it in
 * crypto->client_handshake_write_key or server_handshake_write_key.
 *
 * @param crypto  Crypto state; c/s_handshake_write_key is set on success.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HS_WRITE_KEY_EXPAND_FAILED.
 */
ctls_status_t ctls_handshake_write_key_generate(ctls_crypto_t *crypto,
                                                ctls_entity_t entity);

/**
 * @brief Expand-Label(hs_traffic_secret, "iv", "", 12) → static IV.
 *
 * Derives the handshake IV for the given entity and stores it in
 * crypto->client_handshake_iv_key or server_handshake_iv_key. The IV is
 * XORed with the sequence number at record time (RFC 8446 §5.3).
 *
 * @param crypto  Crypto state; c/s_handshake_iv_key is set on success.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HS_IV_KEY_EXPAND_FAILED.
 */
ctls_status_t ctls_handshake_iv_key_generate(ctls_crypto_t *crypto, ctls_entity_t entity);

/**
 * @brief RFC 5869 HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
 *
 * Both salt and IKM are PSA key handles. The output PRK is stored as a new
 * transient PSA key at *output_key_id. The caller is responsible for
 * destroying the output key when done.
 *
 * @param output_key_id  Output: PSA key handle for the derived PRK.
 * @param salt           PSA key handle of the HKDF salt.
 * @param ikm_key_id     PSA key handle of the input key material.
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_HKDF_EXTRACT_* error.
 */
ctls_status_t ctls_hkdf_extract(psa_key_id_t *output_key_id,
                                psa_key_id_t const *salt,
                                psa_key_id_t const *ikm_key_id);

/**
 * @brief RFC 5869 HKDF-Expand: OKM = T(1)|T(2)|... from PRK and HkdfLabel.
 *
 * Uses psa_key_derivation_setup with the PRK and the HkdfLabel bytes (built
 * by ctls_context_string_build). key_usage selects output key attributes
 * (type, algorithm, bits) via ctls_key_attributes_set.
 *
 * @param output_key_id  Output: PSA key handle for the derived OKM.
 * @param prk_key_id     PSA key handle of the PRK (from ctls_hkdf_extract).
 * @param key_usage      Attribute profile for the output key (one of CTLS_KEY_USAGE_*).
 * @param info           HkdfLabel bytes (from ctls_context_string_build).
 * @param info_length    Length of info in bytes.
 * @return CTLS_STATUS_SUCCESS, or a CTLS_STATUS_CRYPTO_HKDF_EXPAND_* error.
 */
ctls_status_t ctls_hkdf_expand(psa_key_id_t *output_key_id,
                               psa_key_id_t const *prk_key_id,
                               ctls_key_usage_t key_usage,
                               uint8_t const *info,
                               ctls_size_t info_length);

/**
 * @brief Compute the per-record AEAD nonce (RFC 8446 §5.3).
 *
 * Left-pads the sequence number to CTLS_SIZE_NONCE bytes and XORs the result
 * into the static IV exported from iv_key_id. Output is the 12-byte nonce
 * passed to psa_aead_encrypt / psa_aead_decrypt.
 *
 * @param buffer          Output: 12-byte nonce (CTLS_SIZE_NONCE bytes).
 * @param sequence_number Current record sequence number.
 * @param iv_key_id       PSA key handle of the static IV (handshake or application).
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_NONCE_IV_EXPORT_FAILED.
 */
ctls_status_t ctls_nonce_generate(uint8_t *buffer,
                                  uint16_t const *sequence_number,
                                  psa_key_id_t const *iv_key_id);

/**
 * @brief AEAD decrypt (AES-GCM open): ciphertext → plaintext.
 *
 * Calls psa_aead_decrypt with the nonce derived from sequence_number and
 * the unified header bytes as additional authenticated data (aad). A tag
 * mismatch fails with CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED, which
 * authenticates both the ciphertext and the aad/header.
 *
 * @param write_key_id    PSA key handle for the AEAD key (read key for decryption).
 * @param iv_key_id       PSA key handle of the static IV; used by ctls_nonce_generate.
 * @param sequence_number Record sequence number (used for nonce derivation).
 * @param aad             Additional authenticated data (unified header bytes).
 * @param aad_len         Length of aad in bytes.
 * @param ciphertext      Input: ciphertext || GCM tag (tag is last 16 bytes).
 * @param ciphertext_len  Total length of ciphertext including the 16-byte tag.
 * @param buffer          Output: decrypted plaintext; must be at least ciphertext_len - 16 bytes.
 * @param bytes_written   Output: number of plaintext bytes written.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED.
 */
ctls_status_t ctls_decrypt(psa_key_id_t const *write_key_id,
                           psa_key_id_t const *iv_key_id,
                           uint16_t const *sequence_number,
                           uint8_t const *aad,
                           size_t aad_len,
                           const uint8_t *ciphertext,
                           size_t ciphertext_len,
                           uint8_t *buffer,
                           size_t *bytes_written);

/**
 * @brief AEAD encrypt (AES-GCM seal): plaintext → ciphertext || tag.
 *
 * Inverse of ctls_decrypt. Output layout is ciphertext_buffer[0..n-1] =
 * encrypted payload, ciphertext_buffer[n..n+15] = 16-byte GCM tag.
 *
 * @param write_key_id       PSA key handle for the AEAD key.
 * @param iv_key_id          PSA key handle of the static IV.
 * @param sequence_number    Record sequence number (for nonce derivation).
 * @param aad                Additional authenticated data (unified header bytes).
 * @param aad_len            Length of aad in bytes.
 * @param plaintext          Input: plaintext to encrypt.
 * @param plaintext_length   Length of plaintext in bytes.
 * @param ciphertext_buffer  Output: ciphertext || tag; must be at least
 *                           plaintext_length + PSA_AEAD_TAG_MAX_SIZE bytes.
 * @param bytes_written      Output: total bytes written (plaintext_length + 16).
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_AEAD_ENCRYPT_FAILED.
 */
ctls_status_t ctls_encrypt(psa_key_id_t const *write_key_id,
                           psa_key_id_t const *iv_key_id,
                           uint16_t const *sequence_number,
                           uint8_t const *aad,
                           ctls_size_t aad_len,
                           uint8_t const *plaintext,
                           ctls_size_t plaintext_length,
                           uint8_t *ciphertext_buffer,
                           size_t *bytes_written);

/**
 * @brief Locate the raw Ed25519 public key material in a DER certificate.
 *
 * Scans certificate_der for the SubjectPublicKeyInfo OID pattern
 * (OID 1.3.101.112 = id-Ed25519) and sets *offset to the byte immediately
 * after the BIT STRING header, where the 32-byte raw key starts.
 * Avoids a full X.509 parser on the constrained target.
 *
 * @param certificate_der         DER-encoded X.509 certificate.
 * @param certificate_der_length  Length of certificate_der in bytes.
 * @param offset                  Output: byte offset of the raw public key material.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_CERT_SPKI_NOT_FOUND.
 */
ctls_status_t ctls_certificate_bytes_offset_find(uint8_t const *certificate_der,
                                                 size_t certificate_der_length,
                                                 ctls_size_t *offset);

/**
 * @brief Import an Ed25519 private key from PKCS#8 DER into a PSA signing key.
 *
 * Parses private_certificate_der to locate the raw Ed25519 key material and
 * imports it into a transient PSA key configured for PSA_ALG_PURE_EDDSA.
 *
 * @param private_certificate_der         DER-encoded PKCS#8 private key.
 * @param private_certificate_der_length  Length of private_certificate_der.
 * @param key_pair_id                     Output: PSA key handle for the signing key.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_CERT_KEY_PAIR_IMPORT_FAILED.
 */
ctls_status_t ctls_certificate_key_pair_import(uint8_t const *private_certificate_der,
                                               size_t private_certificate_der_length,
                                               psa_key_id_t *key_pair_id);

/**
 * @brief Extract and import an Ed25519 public key from a DER certificate.
 *
 * Uses ctls_certificate_bytes_offset_find to locate the SubjectPublicKeyInfo
 * (OID 1.3.101.112) and imports the raw 32-byte public key as a PSA verify key
 * configured for PSA_ALG_PURE_EDDSA.
 *
 * @param public_certificate_der         DER-encoded X.509 certificate.
 * @param public_certificate_der_length  Length of public_certificate_der.
 * @param key_id                         Output: PSA key handle for the verify key.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_CERT_PUB_KEY_IMPORT_FAILED.
 */
ctls_status_t ctls_certificate_public_key_import(uint8_t const *public_certificate_der,
                                                 size_t public_certificate_der_length,
                                                 psa_key_id_t *key_id);

/**
 * @brief Produce the CertificateVerify signature (RFC 8446 §4.4.3).
 *
 * Builds the signed content (64 × 0x20 | context string | 0x00 | Transcript-Hash)
 * via ctls_context_string_build, then signs it with Ed25519 using
 * crypto->self_certificate_key_pair. Result is written to
 * hshk_data->client_signature or hshk_data->server_signature.
 *
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects context string and output).
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_SIGNATURE_FAILED.
 */
ctls_status_t ctls_signed_bytes_generate(ctls_entity_t entity);

/**
 * @brief Verify the peer's CertificateVerify against the §4.4.3 signed content.
 *
 * Reconstructs the signed content for the peer entity, then verifies the
 * signature from hshk_data->client_signature or server_signature against
 * public_key_id (the peer's imported Ed25519 public key).
 *
 * @param public_key_id  PSA key handle of the peer's Ed25519 verify key.
 * @param entity         CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER (selects context string and signature).
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_SIGNATURE_VERIFY_FAILED.
 */
ctls_status_t ctls_signed_bytes_verify(psa_key_id_t const *public_key_id,
                                       ctls_entity_t entity);

/**
 * @brief Derive the Finished key: HKDF-Expand-Label(base_key, "finished", "", 32).
 *
 * Stores the result in crypto->client_finished_key or server_finished_key
 * (selected by entity). Called once per entity before ctls_verify_data_generate.
 *
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_FINISHED_KEY_EXPAND_FAILED.
 */
ctls_status_t ctls_finished_key_generate(ctls_entity_t entity);

/**
 * @brief Compute Finished verify_data: HMAC(finished_key, Transcript-Hash).
 *
 * Per RFC 8446 §4.4.4. Uses the finished key for entity, snapshots the
 * current transcript hash, and writes the HMAC result to
 * hshk_data->client_verify_data or server_verify_data.
 *
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @param verify_data buffer to store the generated bytes(output buffer)
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_HMAC_VERIFY_DATA_FAILED.
 */
ctls_status_t ctls_verify_data_generate(ctls_entity_t entity, uint8_t *verify_data);

/**
 * @brief Destroy every PSA key that's exclusively handshake-scoped.
 *
 * Frees the ephemeral ECDHE pair, shared secret, early/handshake secrets,
 * handshake traffic/write/IV keys (both entities), certificate signing and
 * peer-verification keys, and Finished keys — everything the handshake
 * produced that application_key_schedule no longer needs. Also zeroes
 * hshk_data's CertificateVerify signature and Finished verify_data bytes
 * (both entities), since they're only needed to authenticate the handshake
 * itself.
 *
 * crypto->handshake_secret and crypto->derived_secret are deliberately left
 * alone: ctls_master_secret_generate (the first step of
 * ctls_application_key_schedule, called right after this) still needs
 * handshake_secret to compute Master Secret's salt (overwriting
 * derived_secret with that fresh value) — it destroys both itself once
 * master_secret is produced.
 *
 * Exists because PSA's default key-slot limit (16 on mbed TLS) is smaller
 * than the number of keys a full handshake-plus-application-phase
 * connection needs concurrently — without this, application_key_schedule's
 * first key import fails with PSA_ERROR_INSUFFICIENT_MEMORY once 16
 * handshake-scoped keys are already live.
 *
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_NULL_STRUCT if crypto or
 *         hshk_data aren't initialized.
 */
ctls_status_t ctls_handshake_keys_cleanup(void);

/**
 * @brief Run the post-Finished key schedule (RFC 8446 §7.1 second half).
 *
 * Derives master_secret → application traffic secrets → application write
 * keys and IVs for both entities, then bumps the epoch twice. Call after
 * both Finished messages are verified and CTLS_HSHK_STATE_CONNECTED is set.
 * Calls ctls_handshake_keys_cleanup() first to free the PSA key slots the
 * handshake-only keys were holding.
 *
 * @return CTLS_STATUS_SUCCESS, or the first CTLS_STATUS_CRYPTO_* error.
 */
ctls_status_t ctls_application_key_schedule(void);

/**
 * @brief Derive master_secret: HKDF-Extract(derived_secret2, 0).
 *
 * derived_secret2 = Expand-Label(handshake_secret, "derived", H(""), 32).
 * Writes result to crypto->master_secret.
 *
 * @param crypto  Crypto state; master_secret is set on success.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_MASTER_SECRET_EXTRACT_FAILED.
 */
ctls_status_t ctls_master_secret_generate(ctls_crypto_t *crypto);

/**
 * @brief Expand-Label(master_secret, "c|s ap traffic", Transcript-Hash, 32).
 *
 * Derives the client or server application traffic secret. Result stored in
 * crypto->client_application_traffic_secret or server_application_traffic_secret.
 *
 * @param crypto  Crypto state; c/s_application_traffic_secret is set on success.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_APP_TRAFFIC_SECRET_EXPAND_FAILED.
 */
ctls_status_t ctls_application_traffic_secret_generate(
    ctls_crypto_t *crypto,
    ctls_entity_t entity);

/**
 * @brief Expand-Label(master_secret, "exp master", Transcript-Hash, 32).
 *
 * Stores result in crypto->exporter_master_secret. Not called by
 * ctls_application_key_schedule — placeholder for RFC 8446 §7.5 exporter support.
 *
 * @param crypto  Crypto state; exporter_master_secret is set on success.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_EXPORTER_SECRET_EXPAND_FAILED.
 */
ctls_status_t ctls_exporter_master_secret_generate(ctls_crypto_t *crypto);

/**
 * @brief Expand-Label(app_traffic_secret, "key", "", 16) → application write key.
 *
 * Stores result in crypto->client_application_write_key or
 * server_application_write_key.
 *
 * @param crypto  Crypto state; c/s_application_write_key is set on success.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_APP_WRITE_KEY_EXPAND_FAILED.
 */
ctls_status_t ctls_application_write_key_generate(ctls_crypto_t *crypto,
                                                  ctls_entity_t entity);

/**
 * @brief Expand-Label(app_traffic_secret, "iv", "", 12) → application IV.
 *
 * Stores result in crypto->client_application_iv_key or
 * server_application_iv_key.
 *
 * @param crypto  Crypto state; c/s_application_iv_key is set on success.
 * @param entity  CTLS_ENTITY_CLIENT or CTLS_ENTITY_SERVER.
 * @return CTLS_STATUS_SUCCESS, or CTLS_STATUS_CRYPTO_APP_IV_KEY_EXPAND_FAILED.
 */
ctls_status_t ctls_application_iv_key_generate(ctls_crypto_t *crypto,
                                               ctls_entity_t entity);

#endif // CTLS_CRYPTO_H
