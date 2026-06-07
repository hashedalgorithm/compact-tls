// Created by Sanjay Kumar Kumaravelan on 19/04/26.

#ifndef CTLS_CRYPTO_H
#define CTLS_CRYPTO_H

#include <psa/crypto.h>
#include "types.h"

#define CTLS_SIZE_NONCE 12U
#define CTLS_SIZE_TRANSCRIPT_HASH 32U

typedef enum {
    CTLS_KEY_TYPE_DERIVED_SECRET = 0,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_SECRET,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_KEYS,
    CTLS_KEY_TYPE_HANDSHAKE_TRAFFIC_IV_KEY,
    CTLS_KEY_TYPE_SIGNED_BYTES,
    CTLS_KEY_TYPE_FINISHED_KEY,
} ctls_key_type_t;

struct ctls_crypto {
    psa_algorithm_t hash_algorithm;
    psa_hash_operation_t transcript_hash_operator;
    psa_ecc_family_t ecdhe_key_pair_type;
    psa_key_id_t server_private_ephemeral_key_id;
    psa_key_id_t client_private_ephemeral_key_id;
    psa_key_derivation_operation_t key_schedule_operator;
};

ctls_status_t ctls_psa_error_map(psa_status_t status);
ctls_status_t ctls_crypto_init();
ctls_status_t ctls_psa_hash_algorithm_set(ctls_crypto_t *crypto,
                                          ctls_cipher_suite_t cipher_suite);
ctls_status_t ctls_psa_ecc_family_set(ctls_crypto_t *crypto,
                                      ctls_dhe_group_t dhe_group_type);
ctls_status_t ctls_transcript_hash_init(ctls_crypto_t *crypto,
                                        uint8_t *transcript_hash,
                                        ctls_template_t const *template);
ctls_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                             uint8_t *transcript_hash);
ctls_status_t ctls_transcript_hash_update(ctls_record_t const *record);
ctls_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                  uint8_t *buffer);

ctls_status_t ctls_hkdf_init(ctls_crypto_t *crypto, ctls_dhe_group_t ecdhe_group_type);
ctls_status_t ctls_key_schedule_operator_reset(ctls_crypto_t *crypto);
ctls_status_t ctls_ephemeral_public_key_generate(uint8_t *buffer,
                                                 ctls_size_t *bytes_written);
ctls_status_t ctls_random_generate(uint8_t *buffer,
                                   ctls_size_t *bytes_written,
                                   uint8_t random_size);
ctls_status_t ctls_key_schedule();
ctls_status_t ctls_context_string_build(uint8_t *buffer,
                                        ctls_size_t *offset,
                                        uint8_t const *transcript_hash,
                                        ctls_entity_t entity,
                                        ctls_key_type_t key_type);
ctls_status_t ctls_early_secret_generate(ctls_crypto_t *crypto, uint8_t *early_secret);
ctls_status_t ctls_derived_secret_generate(ctls_crypto_t *crypto,
                                           ctls_hshk_data_t *hshk_data);
ctls_status_t ctls_shared_ephemeral_secret_generate(ctls_crypto_t const *crypto,
                                                    ctls_hshk_data_t *hshk_data);
ctls_status_t ctls_handshake_secret_generate(ctls_crypto_t *crypto,
                                             ctls_hshk_data_t *hshk_data);
ctls_status_t ctls_handshake_traffic_secret_generate(ctls_crypto_t *crypto,
                                                     ctls_hshk_data_t *hshk_data,
                                                     ctls_entity_t entity);
ctls_status_t ctls_handshake_key_generate(ctls_crypto_t *crypto,
                                          ctls_hshk_data_t *hshk_data,
                                          ctls_entity_t entity);
ctls_status_t ctls_handshake_iv_key_generate(ctls_crypto_t *crypto,
                                             ctls_hshk_data_t *hshk_data,
                                             ctls_entity_t entity);
ctls_status_t ctls_nonce_generate(uint8_t *buffer,
                                  uint16_t const *sequence_number,
                                  uint8_t const *iv_key);
ctls_status_t ctls_decrypt(uint16_t const *seq_num,
                           uint8_t const *aad,
                           size_t aad_len,
                           const uint8_t *ciphertext,
                           size_t ciphertext_len,
                           uint8_t *buffer,
                           size_t *bytes_written);

ctls_status_t ctls_cert_public_key_import(uint8_t const *cert_der,
                                          size_t cert_der_length,
                                          psa_key_id_t *key_id);
ctls_status_t ctls_signed_bytes_generate(ctls_entity_t entity);
ctls_status_t ctls_signed_bytes_verify(ctls_entity_t entity);
#endif //CTLS_CRYPTO_H
