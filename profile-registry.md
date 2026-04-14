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
| --------- | -------------------------------------------- | ----------------- | ------- |
| `0x1301`  | `CTLS_CIPHER_SUITE_AES_128_GCM_SHA256`       | AES-128-GCM       | SHA-256 |
| `0x1302`  | `CTLS_CIPHER_SUITE_AES_256_GCM_SHA384`       | AES-256-GCM       | SHA-384 |
| `0x1303`  | `CTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | SHA-256 |
| `0x1304`  | `CTLS_CIPHER_SUITE_AES_128_CCM_SHA256`       | AES-128-CCM       | SHA-256 |
| `0x1305`  | `CTLS_CIPHER_SUITE_AES_128_CCM_8_SHA256`     | AES-128-CCM-8     | SHA-256 |

### DHE Groups

DHE groups are IANA-assigned 2-byte codepoints from RFC 8446 defining the key exchange group.
ECDH groups use elliptic curve Diffie-Hellman. FFDH groups use finite-field Diffie-Hellman.

| Hex Value | Enum Name                  | Type | Notes                                                      |
| --------- | -------------------------- | ---- | ---------------------------------------------------------- |
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
| --------- | ------------------------------------- | ----- | -------- | ---------------------------- |
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

- **ECDSA + mismatched curve**: `ECDSA_SECP256R1_SHA256` requires `SECP256R1` DHE group. Using it with `X25519` or `SECP384R1` is invalid.
- **ED25519 + non-X25519**: `ED25519` requires `X25519` DHE group exclusively.
- **ED448 + non-X448**: `ED448` requires `X448` DHE group exclusively.
- **FFDHE + ECDSA/EdDSA**: Finite-field DH groups (`FFDHE2048`, `FFDHE3072`, `FFDHE4096`) are incompatible with elliptic curve and Edwards curve signature algorithms.

---

## Profile Table

All 385 valid profile combinations. Version is always `0x0304` (TLS 1.3).

| Profile ID | Cipher Suite               | Cipher Hex | DHE Group   | Group Hex | Signature Algorithm      | Sig Hex  |
| ---------- | -------------------------- | ---------- | ----------- | --------- | ------------------------ | -------- |
| `0x01`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x02`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x03`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x04`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `ECDSA_SECP256R1_SHA256` | `0x0403` |
| `0x05`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x06`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x07`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x08`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x09`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x0A`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x0B`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x0C`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x0D`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x0E`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `ECDSA_SECP384R1_SHA384` | `0x0503` |
| `0x0F`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x10`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x11`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x12`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x13`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x14`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x15`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x16`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x17`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x18`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `ECDSA_SECP521R1_SHA512` | `0x0603` |
| `0x19`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x1A`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x1B`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x1C`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x1D`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x1E`     | `AES_128_GCM_SHA256`       | `0x1301`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x1F`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x20`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x21`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x22`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x23`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x24`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x25`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `ED25519`                | `0x0807` |
| `0x26`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x27`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x28`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x29`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x2A`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x2B`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x2C`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x2D`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x2E`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x2F`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `ED448`                  | `0x0808` |
| `0x30`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x31`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x32`     | `AES_128_GCM_SHA256`       | `0x1301`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x33`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x34`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x35`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x36`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x37`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x38`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x39`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x3A`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x3B`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x3C`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x3D`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x3E`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x3F`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x40`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x41`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x42`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x43`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x44`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x45`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x46`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x47`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x48`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x49`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x4A`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x4B`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x4C`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x4D`     | `AES_128_GCM_SHA256`       | `0x1301`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x4E`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x4F`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x50`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x51`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `ECDSA_SECP256R1_SHA256` | `0x0403` |
| `0x52`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x53`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x54`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x55`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x56`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x57`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x58`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x59`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x5A`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x5B`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `ECDSA_SECP384R1_SHA384` | `0x0503` |
| `0x5C`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x5D`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x5E`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x5F`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x60`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x61`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x62`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x63`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x64`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x65`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `ECDSA_SECP521R1_SHA512` | `0x0603` |
| `0x66`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x67`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x68`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x69`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x6A`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x6B`     | `AES_256_GCM_SHA384`       | `0x1302`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x6C`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x6D`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x6E`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x6F`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x70`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x71`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x72`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `ED25519`                | `0x0807` |
| `0x73`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x74`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x75`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x76`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x77`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x78`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x79`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x7A`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x7B`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x7C`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `ED448`                  | `0x0808` |
| `0x7D`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x7E`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x7F`     | `AES_256_GCM_SHA384`       | `0x1302`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x80`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x81`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x82`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x83`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x84`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x85`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x86`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x87`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x88`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x89`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x8A`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x8B`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x8C`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x8D`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x8E`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x8F`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x90`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x91`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x92`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x93`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x94`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x95`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x96`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x97`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x98`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x99`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x9A`     | `AES_256_GCM_SHA384`       | `0x1302`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x9B`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x9C`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x9D`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x9E`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `ECDSA_SECP256R1_SHA256` | `0x0403` |
| `0x9F`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xA0`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xA1`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xA2`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xA3`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xA4`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xA5`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xA6`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xA7`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xA8`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `ECDSA_SECP384R1_SHA384` | `0x0503` |
| `0xA9`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xAA`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xAB`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xAC`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xAD`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xAE`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xAF`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xB0`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xB1`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xB2`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `ECDSA_SECP521R1_SHA512` | `0x0603` |
| `0xB3`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xB4`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xB5`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xB6`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xB7`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xB8`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xB9`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xBA`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xBB`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xBC`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xBD`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xBE`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xBF`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `ED25519`                | `0x0807` |
| `0xC0`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xC1`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xC2`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xC3`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xC4`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xC5`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xC6`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xC7`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xC8`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xC9`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `ED448`                  | `0x0808` |
| `0xCA`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xCB`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xCC`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xCD`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xCE`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xCF`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xD0`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xD1`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xD2`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xD3`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xD4`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xD5`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xD6`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xD7`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xD8`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xD9`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xDA`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xDB`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xDC`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xDD`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xDE`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xDF`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xE0`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xE1`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xE2`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xE3`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xE4`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xE5`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xE6`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xE7`     | `CHACHA20_POLY1305_SHA256` | `0x1303`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xE8`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xE9`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xEA`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xEB`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `ECDSA_SECP256R1_SHA256` | `0x0403` |
| `0xEC`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xED`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xEE`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xEF`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xF0`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xF1`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xF2`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xF3`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xF4`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xF5`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `ECDSA_SECP384R1_SHA384` | `0x0503` |
| `0xF6`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0xF7`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0xF8`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0xF9`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0xFA`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0xFB`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0xFC`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0xFD`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0xFE`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0xFF`     | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `ECDSA_SECP521R1_SHA512` | `0x0603` |
| `0x100`    | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x101`    | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x102`    | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x103`    | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x104`    | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x105`    | `AES_128_CCM_SHA256`       | `0x1304`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x106`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x107`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x108`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x109`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x10A`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x10B`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x10C`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `ED25519`                | `0x0807` |
| `0x10D`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x10E`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x10F`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x110`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x111`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x112`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x113`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x114`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x115`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x116`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `ED448`                  | `0x0808` |
| `0x117`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x118`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x119`    | `AES_128_CCM_SHA256`       | `0x1304`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x11A`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x11B`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x11C`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x11D`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x11E`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x11F`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x120`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x121`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x122`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x123`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x124`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x125`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x126`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x127`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x128`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x129`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x12A`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x12B`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x12C`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x12D`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x12E`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x12F`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x130`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x131`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x132`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x133`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x134`    | `AES_128_CCM_SHA256`       | `0x1304`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x135`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x136`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x137`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x138`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `ECDSA_SECP256R1_SHA256` | `0x0403` |
| `0x139`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x13A`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x13B`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x13C`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x13D`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x13E`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP256R1` | `0x0017`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x13F`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x140`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x141`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x142`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `ECDSA_SECP384R1_SHA384` | `0x0503` |
| `0x143`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x144`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x145`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x146`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x147`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x148`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP384R1` | `0x0018`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x149`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x14A`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x14B`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x14C`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `ECDSA_SECP521R1_SHA512` | `0x0603` |
| `0x14D`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x14E`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x14F`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x150`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x151`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x152`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `SECP521R1` | `0x0019`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x153`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x154`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x155`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x156`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x157`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x158`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x159`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `ED25519`                | `0x0807` |
| `0x15A`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x15B`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x15C`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X25519`    | `0x001D`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x15D`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x15E`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x15F`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x160`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x161`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x162`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x163`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `ED448`                  | `0x0808` |
| `0x164`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x165`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x166`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `X448`      | `0x001E`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x167`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x168`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x169`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x16A`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x16B`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x16C`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x16D`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x16E`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x16F`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE2048` | `0x0100`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x170`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x171`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x172`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x173`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x174`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x175`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x176`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x177`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x178`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE3072` | `0x0101`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |
| `0x179`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA256`       | `0x0401` |
| `0x17A`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA384`       | `0x0501` |
| `0x17B`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PKCS1_SHA512`       | `0x0601` |
| `0x17C`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA256`    | `0x0804` |
| `0x17D`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA384`    | `0x0805` |
| `0x17E`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_RSAE_SHA512`    | `0x0806` |
| `0x17F`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA256`     | `0x0809` |
| `0x180`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA384`     | `0x080A` |
| `0x181`    | `AES_128_CCM_8_SHA256`     | `0x1305`   | `FFDHE4096` | `0x0102`  | `RSA_PSS_PSS_SHA512`     | `0x080B` |

---

_Generated from draft-ietf-tls-ctls-10 and RFC 8446 IANA registry. Profile IDs are assigned sequentially — they carry no meaning beyond identifying a fixed parameter set in this registry._
