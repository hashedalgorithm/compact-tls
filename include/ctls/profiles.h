//
// Created by Sanjay Kumar Kumaravelan on 31/03/26.
//


#ifndef LPWAN_CTLS_CLIENT_PROFILES_H
#define LPWAN_CTLS_CLIENT_PROFILES_H

#include <stddef.h>
#include "types.h"

#if CTLS_SERVER
static const ctls_profile_t CTLS_PROFILES[] = {
    // AES-128-GCM + X25519 + ECDSA_P256
    {
        .profile_id = 0x01,
        .version = CTLS_VERSION_1_3,
        .cipher_suite = CTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        .dhe_group = CTLS_DHE_GROUP_X25519,
        .signature_algorithm = CTLS_SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256,
        .certificate = NULL,
        .certificate_length = 0,
    },
    // AES-128-GCM + SECP256R1 + ECDSA_P256
    {
        .profile_id = 0x02,
        .version = CTLS_VERSION_1_3,
        .cipher_suite = CTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        .dhe_group = CTLS_DHE_GROUP_SECP256R1,
        .signature_algorithm = CTLS_SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256,
        .certificate = NULL,
        .certificate_length = 0,
    },
};

#endif


#endif
