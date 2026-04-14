# cTLS Profile Registry

**Reference:** draft-ietf-tls-ctls-10  
**Total valid profiles:** 385  
**Version:** TLS 1.3 (0x0304) — fixed for all profiles

---

## Purpose

This document is the external source of truth for cTLS profile definitions used by the `ctls` library.
A profile defines a fixed set of cryptographic parameters agreed between client and server out-of-band.
The client references a profile ID in `ctls_config.h` and hardcodes the matching parameter values.
The server holds a table of all supported profiles and matches against the client's proposed profile ID.
If parameters do not match the registered definition, the handshake will fail — this is by design.

---

## How to Use

1. Find your desired combination in the table below.
2. Note the `Profile ID`, `CTLS_CIPHER_SUITE`, `CTLS_DHE_GROUP`, and `CTLS_SIGNATURE_ALGORITHM` values.
3. Set these in your `ctls_config.h`:

```c
// ctls_config.h
#define CTLS_PROFILE_ID                 0x01     // from Profile ID column
#define CTLS_CIPHER_SUITE               0x1305   // from Cipher Suite column
#define CTLS_DHE_GROUP                  0x001D   // from DHE Group column
#define CTLS_SIGNATURE_ALGORITHM        0x0807   // from Signature Algorithm column
```

---

## Parameter Reference

### Cipher Suites

Cipher suites are IANA-assigned 2-byte codepoints from RFC 8446 (TLS 1.3).
Each suite specifies an AEAD algorithm for record encryption and a hash algorithm for the key schedule.

| Hex Value | Enum Name                                    | AEAD Algorithm    | Hash    |
|-----------|----------------------------------------------|-------------------|---------|
| `0x1301`  | `CTLS_CIPHER_SUITE_AES_128_GCM_SHA256`       | AES-128-GCM       | SHA-256 |
| `0x1302`  | `CTLS_CIPHER_SUITE_AES_256_GCM_SHA384`       | AES-256-GCM       | SHA-384 |
| `0x1303`  | `CTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | SHA-256 |
| `0x1304`  | `CTLS_CIPHER_SUITE_AES_128_CCM_SHA256`       | AES-128-CCM       | SHA-256 |
| `0x1305`  | `CTLS_CIPHER_SUITE_AES_128_CCM_8_SHA256`     | AES-128-CCM-8     | SHA-256 |

### DHE Groups

DHE groups are IANA-assigned 2-byte codepoints from RFC 8446 defining the key exchange group.
ECDH groups use elliptic curve Diffie-Hellman. FFDH groups use finite-field Diffie-Hellman.

| Hex Value | Enum Name                  | Type | Notes                                                      |
|-----------|----------------------------|------|------------------------------------------------------------|
| `0x0017`  | `CTLS_DHE_GROUP_SECP256R1` | ECDH | NIST P-256, hardware-accelerated on STM32L4 PKA            |
| `0x0018`  | `CTLS_DHE_GROUP_SECP384R1` | ECDH | NIST P-384                                                 |
| `0x0019`  | `CTLS_DHE_GROUP_SECP521R1` | ECDH | NIST P-521                                                 |
| `0x001D`  | `CTLS_DHE_GROUP_X25519`    | ECDH | Curve25519, compact 32-byte keys, recommended for embedded |
| `0x001E`  | `CTLS_DHE_GROUP_X448`      | ECDH | Curve448, 56-byte keys                                     |
| `0x0100`  | `CTLS_DHE_GROUP_FFDHE2048` | FFDH | Classic DH 2048-bit, RSA sig algs only                     |
| `0x0101`  | `CTLS_DHE_GROUP_FFDHE3072` | FFDH | Classic DH 3072-bit, RSA sig algs only                     |
| `0x0102`  | `CTLS_DHE_GROUP_FFDHE4096` | FFDH | Classic DH 4096-bit, RSA sig algs only                     |

### Signature Algorithms

Signature algorithms are IANA-assigned 2-byte codepoints from RFC 8446.
ECDSA algorithms require the DHE group to use the matching curve.
EdDSA algorithms (ED25519, ED448) require specific DHE groups as noted.
RSA algorithms are compatible with any DHE group.

| Hex Value | Enum Name                             | Type  | Hash     | Curve Constraint             |
|-----------|---------------------------------------|-------|----------|------------------------------|
| `0x0401`  | `CTLS_SIG_ALG_RSA_PKCS1_SHA256`       | RSA   | SHA-256  | None                         |
| `0x0501`  | `CTLS_SIG_ALG_RSA_PKCS1_SHA384`       | RSA   | SHA-384  | None                         |
| `0x0601`  | `CTLS_SIG_ALG_RSA_PKCS1_SHA512`       | RSA   | SHA-512  | None                         |
| `0x0403`  | `CTLS_SIG_ALG_ECDSA_SECP256R1_SHA256` | ECDSA | SHA-256  | Must use SECP256R1 DHE group |
| `0x0503`  | `CTLS_SIG_ALG_ECDSA_SECP384R1_SHA384` | ECDSA | SHA-384  | Must use SECP384R1 DHE group |
| `0x0603`  | `CTLS_SIG_ALG_ECDSA_SECP521R1_SHA512` | ECDSA | SHA-512  | Must use SECP521R1 DHE group |
| `0x0804`  | `CTLS_SIG_ALG_RSA_PSS_RSAE_SHA256`    | RSA   | SHA-256  | None                         |
| `0x0805`  | `CTLS_SIG_ALG_RSA_PSS_RSAE_SHA384`    | RSA   | SHA-384  | None                         |
| `0x0806`  | `CTLS_SIG_ALG_RSA_PSS_RSAE_SHA512`    | RSA   | SHA-512  | None                         |
| `0x0807`  | `CTLS_SIG_ALG_ED25519`                | EDDSA | SHA-512  | Must use X25519 DHE group    |
| `0x0808`  | `CTLS_SIG_ALG_ED448`                  | EDDSA | SHAKE256 | Must use X448 DHE group      |
| `0x0809`  | `CTLS_SIG_ALG_RSA_PSS_PSS_SHA256`     | RSA   | SHA-256  | None                         |
| `0x080A`  | `CTLS_SIG_ALG_RSA_PSS_PSS_SHA384`     | RSA   | SHA-384  | None                         |
| `0x080B`  | `CTLS_SIG_ALG_RSA_PSS_PSS_SHA512`     | RSA   | SHA-512  | None                         |

---

## Exclusion Rules

The following combinations are invalid and excluded from this registry:

- **ECDSA + mismatched curve**: `ECDSA_SECP256R1_SHA256` requires `SECP256R1` DHE group. Using it with `X25519` or
  `SECP384R1` is invalid.
- **ED25519 + non-X25519**: `ED25519` requires `X25519` DHE group exclusively.
- **ED448 + non-X448**: `ED448` requires `X448` DHE group exclusively.
- **FFDHE + ECDSA/EdDSA**: Finite-field DH groups (`FFDHE2048`, `FFDHE3072`, `FFDHE4096`) are incompatible with elliptic
  curve and Edwards curve signature algorithms.

---

## Profile Table

All 385 valid profile combinations. Version is always `0x0304` (TLS 1.3).

```json
// Profile - 0x0001
{
  "ctlsVersion": 0,
  "profile": "0x0001",
  "version": "0x0304",
  "random": 16,
  "cipherSuite": "TLS_AES_128_GCM_SHA256",
  "signatureAlgorithm": {
    "signatureScheme": "ed25519",
    "signatureLength": 64
  },
  "dhGroup": {
    "groupName": "x25519",
    "keyShareLength": 32
  },
  "clientHelloExtensions": {
    "expectedExtensions": [
      "key_share"
    ],
    "allowAdditional": false
  },
  "serverHelloExtensions": {
    "expectedExtensions": [
      "key_share"
    ],
    "allowAdditional": false
  },
  "encryptedExtensions": {
    "allowAdditional": false
  }
}

```

---

_Generated from draft-ietf-tls-ctls-10 and RFC 8446 IANA registry. Profile IDs are assigned sequentially — they carry no
meaning beyond identifying a fixed parameter set in this registry._
