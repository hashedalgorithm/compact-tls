//
// Created by Sanjay Kumar Kumaravelan on 19/04/26.
//

#ifndef CTLS_CRYPTO_H
#define CTLS_CRYPTO_H

#include <psa/crypto.h>
#include "types.h"

struct ctls_transcript_hash {
    uint8_t hash[CTLS_SIZE_TRANSCRIPT_HASH];
    psa_hash_operation_t hash_operator;
    uint64_t offset;
};

ctls_op_status_t ctls_psa_error_map(psa_status_t status);
ctls_op_status_t ctls_crypto_init(ctls_transcript_hash_t *transcript_hash);
ctls_op_status_t ctls_transcript_hash_init(ctls_transcript_hash_t *transcript_hash,
                                           ctls_template_t const *template);
ctls_op_status_t ctls_transcript_hash_calculate(psa_hash_operation_t *hash_operator,
                                                uint8_t const *buffer,
                                                ctls_size_t const *offset);
ctls_op_status_t ctls_transcript_hash_update(ctls_record_t const *record,
                                             ctls_template_t const *template,
                                             ctls_hsmg_type_t type,
                                             psa_hash_operation_t *hash_operator);
ctls_op_status_t transcript_snapshot(psa_hash_operation_t const *hash_operator,
                                     uint8_t *buffer);
ctls_op_status_t ctls_ephemeral_public_key_generate(uint8_t *buffer,
                                                    ctls_size_t *offset,
                                                    ctls_size_t *bytes_written);
);
ctls_op_status_t ctls_random_generate(uint8_t *buffer,
                                      ctls_size_t *offset,
                                      ctls_size_t *bytes_written,
                                      uint8_t random_size);

#endif //CTLS_CRYPTO_H
