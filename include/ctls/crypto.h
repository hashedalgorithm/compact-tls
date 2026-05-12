//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_CRYPTO_H
#define CTLS_CRYPTO_H

#include <psa/crypto.h>
#include "types.h"

#define CTLS_SIZE_TRANSCRIPT_HASH 32U

struct ctls_crypto {
    psa_algorithm_t hash_algorithm;
    psa_hash_operation_t transcript_hash_operator;
    psa_hash_operation_t key_schedule_operator;
};

ctls_op_status_t ctls_psa_error_map(psa_status_t status);
ctls_op_status_t ctls_crypto_init(ctls_crypto_t *crypto,
                                  ctls_template_t const *template,
                                  ctls_hshk_data_t *hshk_data,
                                  ctls_hsmg_cipher_suite_type_t cipher_suite);
ctls_op_status_t ctls_psa_hash_algorithm_set(ctls_crypto_t *crypto,
                                             ctls_hsmg_cipher_suite_type_t cipher_suite);
ctls_op_status_t ctls_transcript_hash_init(ctls_crypto_t *crypto,
                                           uint8_t *transcript_hash,
                                           ctls_template_t const *template);
ctls_op_status_t ctls_hkdf_init(ctls_crypto_t *crypto);

ctls_op_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                                uint8_t *transcript_hash);
ctls_op_status_t ctls_transcript_hash_update(ctls_record_t const *record,
                                             ctls_template_t const *template,
                                             psa_hash_operation_t *hash_operator,
                                             uint8_t *transcript_hash);
ctls_op_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                     uint8_t *buffer);

ctls_op_status_t ctls_ephemeral_public_key_generate(uint8_t *buffer,
                                                    ctls_size_t *bytes_written);
ctls_op_status_t ctls_random_generate(uint8_t *buffer,
                                      ctls_size_t *bytes_written,
                                      uint8_t random_size);

#endif //CTLS_CRYPTO_H
