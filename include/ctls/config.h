//
// Created by Sanjay Kumar Kumaravelan on 03/04/26.
//

#ifndef CTLS_CONFIG_H
#define CTLS_CONFIG_H

#define CTLS_CLIENT  1
#define CTLS_SERVER  0

// default profile parameters — mandatory when CTLS_CLIENT is active

/* Using a wrong profile with wrong paramates results in connection
 * failure. Refer profile-registry.md for profile definitions. */

#define CTLS_PROFILE_ID                 0x01     // Refer profile-registry.md to get respective profileId
#define CTLS_CIPHER_SUIT                0x1301   // CTLS_CIPHER_SUITE_AES_128_CCM_8_SHA256
#define CTLS_DHE_GROUP                  0x001D   // CTLS_DHE_GROUP_X25519
#define CTLS_SIGNATURE_ALGORITHM        0x0807   // CTLS_SIGNATURE_ALGORITHM_ED25519

#endif
