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
 *     this implementation uses "Sctls " (see ctls_context_string_build)
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

/** Map a psa_status_t onto the closest ctls_status_t. */
ctls_status_t ctls_psa_error_map(psa_status_t status);

/**
 * One-time setup: psa_crypto_init, hash algorithm from the template's
 * cipher suite, transcript hash start (template bytes hashed first),
 * HKDF/ECC family selection.
 */
ctls_status_t ctls_crypto_init();
/** Cipher suite -> PSA hash algorithm (suite's HKDF hash, RFC 8446 §B.4). */
ctls_status_t ctls_psa_hash_algorithm_set(ctls_crypto_t *crypto,
                                          ctls_cipher_suite_t cipher_suite);
/** Map a PSA algorithm to its key size in bits (e.g. AES-128-GCM -> 128, HMAC-SHA256 -> 256). */
ctls_status_t ctls_key_bits_get(psa_algorithm_t const *algorithm, ctls_size_t *key_bits);

/** NamedGroup -> PSA ECC/DH family for ephemeral key generation. */
ctls_status_t ctls_psa_ecc_family_set(ctls_crypto_t *crypto,
                                      ctls_dhe_group_t dhe_group_type);

/**
 * Start the running transcript hash and feed the canonical template bytes
 * (ctls_template_to_wire) as its first input — both peers must bind the
 * same template into the transcript.
 */
ctls_status_t ctls_transcript_hash_init(ctls_crypto_t *crypto,
                                        uint8_t *transcript_hash,
                                        ctls_template_t const *template);
/** Feed CTLS_SIZE_TRANSCRIPT_HASH bytes into the running hash operator. */
ctls_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                             uint8_t *transcript_hash);
/**
 * Serialize the record in TRANSCRIPT_HASH wire format (reconstructed
 * TLS 1.3 bytes) and absorb it into the running transcript. Called once
 * per handshake message from the handshake driver.
 */
ctls_status_t ctls_transcript_hash_update(ctls_record_t const *record);
/**
 * Read the current transcript hash without finishing the running operator
 * (psa_hash_clone + finish on the clone).
 */
ctls_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                  uint8_t *buffer);

/** Reset the derivation operator + select ECC family for the profile. */
ctls_status_t ctls_hkdf_init(ctls_crypto_t *crypto, ctls_dhe_group_t ecdhe_group_type);
/** Abort and reinitialize the PSA key derivation operator; required between consecutive Extract/Expand steps. */
ctls_status_t ctls_key_schedule_operator_reset(ctls_crypto_t *crypto);

/** Import raw peer public key bytes (X25519 32-byte point) into PSA as a key-agreement key. */
ctls_status_t ctls_ephemeral_public_key_import(uint8_t const *buffer,
                                               ctls_size_t buffer_length,
                                               psa_key_id_t *ephemeral_public_key);
/** Export the public half of an ephemeral key pair to raw bytes for inclusion in a KeyShare entry. */
ctls_status_t ctls_ephemeral_public_key_export(psa_key_id_t const *ephemeral_key_pair_id,
                                               uint8_t *buffer,
                                               ctls_size_t buffer_length,
                                               ctls_size_t *buffer_bytes_written);

/** Generate an ECDHE key pair into a transient PSA key handle. Public half exported separately via ctls_ephemeral_public_key_export. */
ctls_status_t ctls_ephemeral_key_pair_generate(psa_key_id_t *ephemeral_key_pair_id);
/** random_size bytes from the PSA DRBG (Hello random, RFC 8446 §4.1.2). */
ctls_status_t ctls_random_generate(uint8_t *buffer,
                                   ctls_size_t *bytes_written,
                                   uint8_t random_size);
/**
 * Run the full key schedule (file header diagram): early secret through
 * both handshake traffic keys + IVs, then epoch -> 2 (handshake keys).
 * Call after ServerHello (needs the server key share + transcript).
 */
ctls_status_t ctls_key_schedule();

/** Set PSA key attributes (type, usage, algorithm, bits) appropriate for the given derivation operation. */
ctls_status_t ctls_key_attributes_set(ctls_key_usage_t key_usage,
                                      psa_key_attributes_t *key_attribute);

/**
 * Build the info/content bytes for one derivation or signature: HkdfLabel
 * (RFC 8446 §7.1: length(u16) | label_len(u8) | "Sctls <label>" |
 * context_len(u8) | context) for key types, or the §4.4.3 signing content
 * (64 x 0x20 | context string | 0x00 | transcript hash) for SIGNED_BYTES.
 */
ctls_status_t ctls_context_string_build(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        ctls_entity_t entity,
                                        ctls_key_type_t key_type);

/** Key schedule steps — see the file-header diagram for what each derives. */
ctls_status_t ctls_early_secret_generate(ctls_crypto_t *crypto);
/** Expand-Label(early_secret, "derived", H(""), 32); output used as salt in next Extract. */
ctls_status_t ctls_derived_secret_generate(ctls_crypto_t *crypto);
/** psa_raw_key_agreement(ECDH, self_ephemeral_key_pair, peer_public_ephemeral_key) -> shared_ephemeral_secret. */
ctls_status_t ctls_shared_ephemeral_secret_generate(ctls_crypto_t *crypto);
/** HKDF-Extract(derived_secret, shared_ephemeral_secret) -> handshake_secret. */
ctls_status_t ctls_handshake_secret_generate(ctls_crypto_t *crypto);
/** Expand-Label(handshake_secret, "c|s hs traffic", Transcript-Hash, 32) per entity. */
ctls_status_t ctls_handshake_traffic_secret_generate(ctls_crypto_t *crypto,
                                                     ctls_entity_t entity);
/** Expand-Label(hs_traffic_secret, "key", "", 16) -> AES-128-GCM write key per entity. */
ctls_status_t ctls_handshake_write_key_generate(ctls_crypto_t *crypto,
                                                ctls_entity_t entity);
/** Expand-Label(hs_traffic_secret, "iv", "", 12) -> static IV per entity (XORed with seq num at record time). */
ctls_status_t ctls_handshake_iv_key_generate(ctls_crypto_t *crypto, ctls_entity_t entity);

/** RFC 5869 HKDF-Extract: PRK = HMAC-Hash(salt, IKM); both inputs are PSA key handles. */
ctls_status_t ctls_hkdf_extract(psa_key_id_t *output_key_id,
                                psa_key_id_t const *salt,
                                psa_key_id_t const *ikm_key_id);
/**
 * RFC 5869 HKDF-Expand: OKM = T(1)|T(2)|... from PRK and HkdfLabel info bytes.
 * key_usage selects output key attributes (type, algorithm, bits) via ctls_key_attributes_set.
 */
ctls_status_t ctls_hkdf_expand(psa_key_id_t *output_key_id,
                               psa_key_id_t const *prk_key_id,
                               ctls_key_usage_t key_usage,
                               uint8_t const *info,
                               ctls_size_t info_length);
/**
 * Per-record nonce (RFC 8446 §5.3): sequence number left-padded to IV size,
 * XORed into the static IV.
 */
ctls_status_t ctls_nonce_generate(uint8_t *buffer,
                                  uint16_t const *sequence_number,
                                  psa_key_id_t const *iv_key_id);
/**
 * AEAD open (RFC 8446 §5.2): AES-128-GCM, nonce from sequence number,
 * header bytes as AAD. Fails CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED on tag
 * mismatch — that check authenticates the AAD/header too.
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
/** AEAD seal — inverse of ctls_decrypt; output = ciphertext | tag(16). */
ctls_status_t ctls_encrypt(psa_key_id_t const *write_key_id,
                           psa_key_id_t const *iv_key_id,
                           uint16_t const *sequence_number,
                           uint8_t const *aad,
                           ctls_size_t aad_len,
                           uint8_t const *plaintext,
                           ctls_size_t plaintext_length,
                           uint8_t *ciphertext_buffer,
                           size_t *bytes_written);

/** Scan certificate DER for the Ed25519 SubjectPublicKeyInfo pattern (OID 1.3.101.112) and return byte offset of the raw key material. */
ctls_status_t ctls_certificate_bytes_offset_find(uint8_t const *certificate_der,
                                                 size_t certificate_der_length,
                                                 ctls_size_t *offset);
/** Import the Ed25519 private key from a PKCS#8 DER into a PSA signing key handle. */
ctls_status_t ctls_certificate_key_pair_import(uint8_t const *private_certificate_der,
                                               size_t private_certificate_der_length,
                                               psa_key_id_t *key_pair_id);
/**
 * Pull the raw Ed25519 public key out of a certificate DER by scanning for
 * the SubjectPublicKeyInfo pattern (OID 1.3.101.112) and import it as a
 * PSA verify key. Avoids a full X.509 parser on the constrained target.
 */
ctls_status_t ctls_certificate_public_key_import(uint8_t const *public_certificate_der,
                                                 size_t public_certificate_der_length,
                                                 psa_key_id_t *key_id);

/**
 * Produce the CertificateVerify signature (RFC 8446 §4.4.3): Ed25519 over
 * 64 x 0x20 | context string | 0x00 | Transcript-Hash, using
 * crypto->self_certificate_key_pair. Result written to hshk_data->client/server_signature.
 */
ctls_status_t ctls_signed_bytes_generate(ctls_entity_t entity);
/**
 * Verify the peer's CertificateVerify against the same §4.4.3 content.
 * public_key_id must be the peer's Ed25519 public key imported via
 * ctls_certificate_public_key_import.
 */
ctls_status_t ctls_signed_bytes_verify(psa_key_id_t const *public_key_id,
                                       ctls_entity_t entity);
/** finished_key = HKDF-Expand-Label(base key, "finished", "", 32). */
ctls_status_t ctls_finished_key_generate(ctls_entity_t entity);
/** verify_data = HMAC(finished_key, Transcript-Hash) — RFC 8446 §4.4.4. */
ctls_status_t ctls_verify_data_generate(ctls_entity_t entity);

ctls_status_t ctls_application_key_schedule(ctls_entity_t entity);
ctls_status_t ctls_master_secret_generate(ctls_crypto_t *crypto);
ctls_status_t ctls_application_traffic_secret_generate(
    ctls_crypto_t *crypto,
    ctls_entity_t entity);
ctls_status_t ctls_exporter_master_secret_generate(ctls_crypto_t *crypto);
ctls_status_t ctls_application_write_key_generate(ctls_crypto_t *crypto,
                                                  ctls_entity_t entity);
ctls_status_t ctls_application_iv_key_generate(ctls_crypto_t *crypto,
                                               ctls_entity_t entity);

#endif // CTLS_CRYPTO_H
