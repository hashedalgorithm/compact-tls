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

typedef enum {
    CTLS_DERIVE_OPERATION_EPHEMERAL_GENERATE = 0,
    CTLS_DERIVE_OPERATION_HKDF_EXTRACT,
    CTLS_DERIVE_OPERATION_HKDF_EXPAND,
    CTLS_DERIVE_OPERATION_AEAD_ENCRYPT_OR_DECRYPT,
    CTLS_DERIVE_OPERATION_HMAC,
} ctls_derive_operation_t;

/** Which HkdfLabel / signing context ctls_context_string_build emits. */
typedef enum {
    CTLS_KEY_TYPE_EARLY_SECRET,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_SECRET,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_KEYS,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_IV_KEY,
    CTLS_KEY_TYPE_SIGNED_BYTES,
    CTLS_KEY_TYPE_FINISHED_KEY,
} ctls_key_type_t;

/** PSA state owned by the connection: hash/derivation operators, key ids. */
struct ctls_crypto {
    psa_algorithm_t hash_algorithm;
    psa_hash_operation_t transcript_hash_operator;
    psa_ecc_family_t ecdhe_key_pair_type;
    psa_key_derivation_operation_t key_schedule_operator;
    psa_key_id_t self_ephemeral_key_pair;
    // If client, client ephemeral key pair and respectively.
    psa_key_id_t peer_public_ephemeral_key;
    // If client, server's pubic key and vice versa
    psa_key_id_t shared_ephemeral_secret;
    psa_key_id_t early_secret;
    psa_key_id_t derived_secret;
    psa_key_id_t handshake_secret;
    psa_key_id_t client_handshake_traffic_secret;
    psa_key_id_t server_handshake_traffic_secret;
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
/** DOCS - TODO */
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
ctls_status_t ctls_key_schedule_operator_reset(ctls_crypto_t *crypto);

/** DOCS - TODO */
ctls_status_t ctls_ephemeral_public_key_import(uint8_t const *buffer,
                                               ctls_size_t buffer_length,
                                               psa_key_id_t *ephemeral_public_key);
ctls_status_t ctls_ephemeral_public_key_export(psa_key_id_t const *ephemeral_key_pair_id,
                                               uint8_t *buffer,
                                               ctls_size_t buffer_length,
                                               ctls_size_t *buffer_bytes_written);

/** Generate the client X25519 ephemeral pair; export public half to buffer. */
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

ctls_status_t ctls_key_attributes_set(ctls_derive_operation_t operation,
                                      psa_key_attributes_t *key_attribute);

/**
 * Build the info/content bytes for one derivation or signature: HkdfLabel
 * (RFC 8446 §7.1: length(u16) | label_len(u8) | "Sctls <label>" |
 * context_len(u8) | context) for key types, or the §4.4.3 signing content
 * (64 x 0x20 | context string | 0x00 | transcript hash) for SIGNED_BYTES.
 */
ctls_status_t ctls_context_string_build(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        uint8_t const *transcript_hash,
                                        ctls_entity_t entity,
                                        ctls_key_type_t key_type);

/** Key schedule steps — see the file-header diagram for what each derives. */
ctls_status_t ctls_early_secret_generate(ctls_crypto_t *crypto);
ctls_status_t ctls_derived_secret_generate(ctls_crypto_t *crypto);
/** X25519 ECDH: client private key x server public key share. */
ctls_status_t ctls_shared_ephemeral_secret_generate(ctls_crypto_t *crypto);
ctls_status_t ctls_handshake_secret_generate(ctls_crypto_t *crypto);
ctls_status_t ctls_handshake_traffic_secret_generate(ctls_crypto_t *crypto,
                                                     ctls_entity_t entity);

ctls_status_t ctls_hkdf_extract(psa_key_id_t *output_key_id,
                                psa_key_id_t const *salt,
                                psa_key_id_t const *ikm_key_id);
ctls_status_t ctls_hkdf_expand(psa_key_id_t *output_key_id,
                               psa_key_id_t const *prk_key_id,
                               ctls_derive_operation_t derive_operation,
                               uint8_t const *info,
                               ctls_size_t info_length);
/**
 * Per-record nonce (RFC 8446 §5.3): sequence number left-padded to IV size,
 * XORed into the static IV.
 */
ctls_status_t ctls_nonce_generate(uint8_t *buffer,
                                  uint16_t const *sequence_number,
                                  uint8_t const *iv_key);
/**
 * AEAD open (RFC 8446 §5.2): AES-128-GCM, nonce from sequence number,
 * header bytes as AAD. Fails CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED on tag
 * mismatch — that check authenticates the AAD/header too.
 */
ctls_status_t ctls_decrypt(uint16_t const *sequence_number,
                           uint8_t const *aad,
                           size_t aad_len,
                           const uint8_t *ciphertext,
                           size_t ciphertext_len,
                           uint8_t *buffer,
                           size_t *bytes_written);
/** AEAD seal — inverse of ctls_decrypt; output = ciphertext | tag(16). */
ctls_status_t ctls_encrypt(uint16_t const *sequence_number,
                           uint8_t const *aad,
                           ctls_size_t aad_len,
                           uint8_t const *plaintext,
                           ctls_size_t plaintext_length,
                           uint8_t *ciphertext_buffer,
                           size_t *bytes_written);

/**
 * Pull the raw Ed25519 public key out of a certificate DER by scanning for
 * the SubjectPublicKeyInfo pattern (OID 1.3.101.112) and import it as a
 * PSA verify key. Avoids a full X.509 parser on the constrained target.
 */
ctls_status_t ctls_cert_public_key_import(uint8_t const *cert_der,
                                          size_t cert_der_length,
                                          psa_key_id_t *key_id);
/**
 * Produce the CertificateVerify signature (RFC 8446 §4.4.3): Ed25519 over
 * 64 x 0x20 | context string | 0x00 | Transcript-Hash, using this entity's
 * PKCS#8 private key from the certs header. Result lands in hshk_data.
 */
ctls_status_t ctls_signed_bytes_generate(ctls_entity_t entity);
/** Verify the peer's CertificateVerify signature against the same content. */
ctls_status_t ctls_signed_bytes_verify(ctls_entity_t entity);
/** finished_key = HKDF-Expand-Label(base key, "finished", "", 32). */
ctls_status_t ctls_finished_key_generate(ctls_entity_t entity);
/** verify_data = HMAC(finished_key, Transcript-Hash) — RFC 8446 §4.4.4. */
ctls_status_t ctls_verify_data_generate(ctls_entity_t entity);
#endif // CTLS_CRYPTO_H
