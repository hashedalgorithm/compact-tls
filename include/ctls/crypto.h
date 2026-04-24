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

ctls_op_status_t ctls_map_psa_error(psa_status_t status);
ctls_op_status_t ctls_init_crypto(ctls_transcript_hash_t *transcript_hash);
ctls_op_status_t ctls_calculate_transcript_hash(
    psa_hash_operation_t *hash_operator,
    uint8_t const *buffer, size_t const *offset);
ctls_op_status_t ctls_update_transcript_hash(ctls_record_t const *record,
                                             ctls_template_t const *template,
                                             psa_hash_operation_t *
                                             hash_operator);
ctls_op_status_t transcript_snapshot(psa_hash_operation_t *hash_operator,
                                     uint8_t *buffer);
ctls_op_status_t ctls_ephemeral_public_key_generate(
    uint8_t *buffer, size_t buffer_length);
ctls_op_status_t ctls_random_generate(uint8_t *buffer);

#endif //CTLS_CRYPTO_H
