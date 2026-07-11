# compact_tls Developer Guide

A from-scratch C implementation of [draft-ietf-tls-ctls](https://datatracker.ietf.org/doc/draft-ietf-tls-ctls/) ("Compact TLS 1.3"). Two peers share a pre-agreed **template** (profile) that pins protocol parameters so they never travel on the wire — that's where the size savings come from.

This document is the API/integration reference. For spec ambiguities, deviations, and compliance status, see [`ambiguities.md`](ambiguities.md). For the full `ctls_status_t` code list, see [`error-codes.md`](error-codes.md). For profile parameter values (cipher suites, DHE groups, signature schemes), see [`profile-registry.md`](profile-registry.md).

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Build-time configuration](#build-time-configuration)
- [The profile (`template.json`)](#the-profile-templatejson)
- [Integrating the library](#integrating-the-library)
- [Public API reference](#public-api-reference)
- [Error handling](#error-handling)
- [Constants reference](#constants-reference)
- [Known limitations](#known-limitations)

---

## Prerequisites

- CMake ≥ 4.1
- A C11 compiler (clang or gcc)
- Internet access on first configure (fetches Mbed TLS source once, cached under `build/_deps`)

[Mbed TLS](https://github.com/Mbed-TLS/mbedtls)'s PSA Crypto backend (`tfpsacrypto`) is pulled in and built from source automatically via CMake `FetchContent` (see `CMakeLists.txt`) — nothing to install system-wide, and no version-matching against whatever your distro's package manager happens to carry. Mbed TLS 4.x (which this project needs for the standalone `tfpsacrypto` target) predates any stable distro package, which is exactly the problem this sidesteps — e.g. Ubuntu/WSL `apt` only has 2.x/3.x, with no PSA Crypto API at this level. The pinned version and build options (static-only, no test suite, no example programs) live in the `FetchContent_Declare(mbedtls ...)` block near the top of `CMakeLists.txt`; bump the `URL`/`URL_HASH` there to move to a newer Mbed TLS release.

---

## Quick start

The library ships two example programs (`examples/client.c`, `examples/server.c`) that run a full handshake and exchange one application-data message. They're the fastest way to see the library work end to end.

### 1. Build

Role (client/server) and transport (reliable/unreliable) are both selected at CMake configure time — see [Build-time configuration](#build-time-configuration) for the full option list.

```sh
# Client (default role, default transport = UDP)
cmake -B build/client -DCTLS_CLIENT=ON -DCTLS_SERVER=OFF
cmake --build build/client

# Server
cmake -B build/server -DCTLS_CLIENT=OFF -DCTLS_SERVER=ON
cmake --build build/server
```

Or use the shortcut script (client/server only, transport left at its UDP default):

```sh
./build.sh client
./build.sh server
```

### 2. Make sure `template.json` exists

Both the client and server binaries load their profile from a JSON file at startup — by default `template.json`, resolved relative to the process's current working directory. The repo root already has a working one for profile `0x01` (`TLS_AES_128_GCM_SHA256` + `x25519` + `ed25519`), so if you run the binaries from the repo root you don't need to do anything. See [The profile](#the-profile-templatejson) to write your own.

### 3. Run the server, then the client

```sh
# terminal 1
./build/server/compact_tls
# listening on 0.0.0.0:4433

# terminal 2
./build/client/compact_tls
# connecting to 127.0.0.1:4433
# ...
# handshake complete
# sent: Hello world!!
```

Both sides print `handshake complete`, exchange one application-data message, and send `close_notify` before exiting. Host/port are hardcoded in the examples (`127.0.0.1:4433`) — edit `examples/client.c`/`examples/server.c` directly to change them, there's no CLI flag.

---

## Build-time configuration

Two independent pairs of mutually-exclusive `option()`s, set via `-D` at `cmake -B` time. CMake will refuse to configure (`FATAL_ERROR`) if a pair isn't exactly one ON.

| Option | Default | Effect |
|---|---|---|
| `CTLS_CLIENT` | `ON` | Build as the client role. Compiles out server-only code paths. |
| `CTLS_SERVER` | `OFF` | Build as the server role. Compiles out client-only code paths. |
| `CTLS_STREAM` | `OFF` | TCP-like framing: unified-header sequence number omitted from the wire, `"Sctls "` HKDF label prefix. |
| `CTLS_DATAGRAM` | `ON` | UDP-like (DTLS 1.3-style) framing: sequence number always on the wire, `"Dctls "` HKDF label prefix. |

Exactly one of `CTLS_CLIENT`/`CTLS_SERVER` must be `ON`, and exactly one of `CTLS_STREAM`/`CTLS_DATAGRAM` must be `ON`. All four combinations build and pass end-to-end.

```sh
# Server, reliable (TCP-like) transport
cmake -B build/server_tcp \
  -DCTLS_CLIENT=OFF -DCTLS_SERVER=ON \
  -DCTLS_STREAM=ON -DCTLS_DATAGRAM=OFF
cmake --build build/server_tcp
```

These are `#define`s baked into the binary (`config.h`'s `#ifndef` guards pick them up from the CMake-injected `target_compile_definitions`) — there's no runtime switch between roles or transports; a build is one role and one transport, permanently.

---

## The profile (`template.json`)

Both peers must load byte-identical parameter values out of band — that's the whole compression trick. This library reads its profile from a JSON file at `ctls_context_init()` time (see [`ctls_template_path_set`](#ctls_template_path_set)), parsed via a vendored, zero-allocation JSON parser ([jsmn](https://github.com/zserge/jsmn), `include/jsmn.h`).

### Minimal example

```json
{
  "ctlsVersion": 0,
  "profile": "0x00000001",
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
    "expectedExtensions": ["key_share"],
    "allowAdditional": false
  },
  "serverHelloExtensions": {
    "expectedExtensions": ["key_share"],
    "allowAdditional": false
  },
  "encryptedExtensions": {
    "allowAdditional": false
  },
  "knownCertificates": {
    "01": "<hex-encoded DER certificate>",
    "02": "<hex-encoded DER certificate>"
  }
}
```

### Field reference

| JSON key | Maps to | Required? | Notes |
|---|---|---|---|
| `profile` | `profile_id` | **Yes** | Hex string, 4 bytes, e.g. `"0x00000001"`. |
| `version` | `protocol_version` | **Yes** | Hex string; must be `"0x0304"` (TLS 1.3) — this implementation only speaks 1.3. |
| `random` | `random` | **Yes** | Plain number, length in bytes of the Hello random. |
| `cipherSuite` | `cipher_suite` | **Yes** | Name string, see [Cipher suites](#cipher-suites) below. |
| `signatureAlgorithm.signatureScheme` | `signature_algorithm.signature_algorithm_type` | **Yes** | Name string, see [Signature schemes](#signature-schemes). |
| `signatureAlgorithm.signatureLength` | `signature_algorithm.signature_length` | **Yes** | Plain number. |
| `dhGroup.groupName` | `dhe_group.dhe_group` | **Yes** | Name string, see [DHE groups](#dhe-groups). |
| `dhGroup.keyShareLength` | `dhe_group.key_share_length` | **Yes** | Plain number. |
| `ctlsVersion` | `ctls_version` | Optional | Plain number, the cTLS encoding version. |
| `clientHelloExtensions` / `serverHelloExtensions` / `encryptedExtensions` | `*_extension` | Optional | Each is `{ "expectedExtensions": [...names...], "allowAdditional": bool }`. Absent block = left untouched (zeroed). |
| `knownCertificates` | `known_certificates` | Optional* | Object keyed by **bare 2-digit hex** certificate id (no `"0x"` prefix), value = hex-encoded DER, e.g. `"01": "3082..."`. Not an array — the key *is* the id. |

\* `known_certificates` is optional in the JSON schema, but [`ctls_validate_template`](#ctls_validate_template) requires at least one entry with a non-empty certificate before the handshake will run — so in practice it's mandatory for any real connection.

`mutual_auth`, `handshake_framing`, `finished_size`, `certificate_request_extension`, and every `predefined_extensions` field (`server_name`, `alpn`, etc.) are **not modeled by the JSON schema at all** — they're left at zero. `mutual_auth`/`handshake_framing` are currently inert (client-certificate auth is unreachable in this implementation's combined-flight model — see `ambiguities.md`), and `finished_size` is unused by the crypto layer today.

#### Cipher suites

| Name | Value |
|---|---|
| `TLS_AES_128_GCM_SHA256` | `0x1301` |
| `TLS_AES_256_GCM_SHA384` | `0x1302` |
| `TLS_CHACHA20_POLY1305_SHA256` | `0x1303` |
| `TLS_AES_128_CCM_SHA256` | `0x1304` |
| `TLS_AES_128_CCM_8_SHA256` | `0x1305` |

#### DHE groups

| Name | Value | Name | Value |
|---|---|---|---|
| `secp256r1` | `0x0017` | `x448` | `0x001E` |
| `secp384r1` | `0x0018` | `ffdhe2048` | `0x0100` |
| `secp521r1` | `0x0019` | `ffdhe3072` | `0x0101` |
| `x25519` | `0x001D` | `ffdhe4096` | `0x0102` |

#### Signature schemes

| Name | Value | Name | Value |
|---|---|---|---|
| `rsa_pkcs1_sha256` | `0x0401` | `rsa_pss_rsae_sha512` | `0x0806` |
| `rsa_pkcs1_sha384` | `0x0501` | `ed25519` | `0x0807` |
| `rsa_pkcs1_sha512` | `0x0601` | `ed448` | `0x0808` |
| `ecdsa_secp256r1_sha256` | `0x0403` | `rsa_pss_pss_sha256` | `0x0809` |
| `ecdsa_secp384r1_sha384` | `0x0503` | `rsa_pss_pss_sha384` | `0x080A` |
| `ecdsa_secp521r1_sha512` | `0x0603` | `rsa_pss_pss_sha512` | `0x080B` |
| `rsa_pss_rsae_sha256` | `0x0804` | | |
| `rsa_pss_rsae_sha384` | `0x0805` | | |

**Note:** only `ecdsa_secp256r1_sha256` (P-256) has a working crypto implementation today (`crypto.c` hardcodes `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`) — the other names parse fine but will fail at the signing/verification step. See `ambiguities.md` §2.

`expectedExtensions` name strings (for the `*HelloExtensions` blocks) match the IANA TLS ExtensionType registry names, e.g. `key_share`, `server_name`, `supported_versions`, `cookie`, `psk_key_exchange_modes` — see `types.h`'s `ctls_extn_type_t` for the full set the parser recognizes.

---

## Integrating the library

The examples are the reference integration, but the shape is always the same three steps: implement a transport, initialize a context, drive the handshake.

### 1. Implement the transport callbacks

```c
typedef ctls_status_t (*ctls_recd_send)(uint8_t *buffer, ctls_size_t buffer_length);
typedef ctls_status_t (*ctls_recd_receive)(uint8_t *buffer, ctls_size_t *buffer_length,
                                           ctls_size_t buffer_size, uint32_t timeout_ms);
```

- `recd_send`: send exactly `buffer_length` bytes from `buffer` over your transport. Return `CTLS_STATUS_SUCCESS` or `CTLS_STATUS_TRANSPORT_SEND_FAILED`.
- `recd_receive`: read up to `buffer_size` bytes into `buffer`, write the actual byte count received into `*buffer_length`. Return `CTLS_STATUS_SUCCESS`, `CTLS_STATUS_TRANSPORT_RECV_FAILED` on a real I/O error, or `CTLS_STATUS_TRANSPORT_TIMEOUT` if `timeout_ms` elapses with no data.

You never call these directly, and you don't own retransmission — every send/receive in the library goes through internal `ctls_send`/`ctls_receive` wrappers (`ctls.c`), which is what actually invokes your callbacks. On `CTLS_DATAGRAM` builds, `ctls_receive` drives `timeout_ms` itself per RFC 9147 §5.8.1/§5.8.2: it starts at `CTLS_DTLS_RETRANSMIT_TIMEOUT_INITIAL_MS` (1000ms), and on each `CTLS_STATUS_TRANSPORT_TIMEOUT` it retransmits the last flight and doubles the wait, capped at `CTLS_DTLS_RETRANSMIT_TIMEOUT_MAX_MS` (60000ms) — both in `config.h`. Your `recd_receive` must actually honor `timeout_ms` (e.g. a fresh `SO_RCVTIMEO` per call) for this enforcement to be real; a callback that ignores it and blocks forever defeats the timer. On `CTLS_STREAM` builds there's no RFC-mandated timeout (RFC 8446 assumes a reliable transport) — `ctls_send`/`ctls_receive` always pass `timeout_ms=0`, meaning "block as usual"; your callback may ignore the parameter.

The library treats the transport as a single logical byte stream/datagram source — it doesn't open sockets, resolve addresses, or manage connections itself. `examples/client.c`/`examples/server.c` show both a TCP and a UDP implementation of this contract, selected by `CTLS_STREAM`.

```c
static ctls_status_t my_send(uint8_t *buffer, ctls_size_t length) {
    ssize_t sent = send(my_socket, buffer, length, 0);
    return (sent < 0) ? CTLS_STATUS_TRANSPORT_SEND_FAILED : CTLS_STATUS_SUCCESS;
}

static ctls_status_t my_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t capacity,
                                uint32_t timeout_ms) {
    struct timeval tv = {.tv_sec = timeout_ms / 1000U, .tv_usec = (timeout_ms % 1000U) * 1000U};
    setsockopt(my_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); /* CTLS_DATAGRAM only */
    ssize_t received = recv(my_socket, buffer, capacity, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return CTLS_STATUS_TRANSPORT_TIMEOUT;
        return CTLS_STATUS_TRANSPORT_RECV_FAILED;
    }
    *length = (ctls_size_t) received;
    return CTLS_STATUS_SUCCESS;
}
```

### 2. Initialize the context

```c
#include "ctls/ctls.h"

ctls_transport_t transport = {.recd_send = my_send, .recd_receive = my_receive};
ctls_context_t ctx;

ctls_status_t result = ctls_context_init(&ctx, &transport, "/etc/myapp/template.json");
if (result != CTLS_STATUS_SUCCESS) {
    // handle CTLS_STATUS_TMPL_PATH_NULL, CTLS_STATUS_TMPL_JSON_FILE_NOT_FOUND,
    // CTLS_STATUS_TMPL_JSON_*, or a CTLS_STATUS_CRYPTO_* init failure
}
```

`template_path` can be any string your `fopen()` can resolve — an absolute path, a path relative to the process's working directory, whatever fits your deployment. There's no compiled-in fallback template: if the file is missing or unparsable, `ctls_context_init` fails with a specific status (see [Error handling](#error-handling)).

### 3. Drive the handshake

```c
// Client:
result = ctls_connect(&ctx);

// Server:
result = ctls_accept(&ctx);
```

Both block on the transport callbacks until the handshake completes or fails. On success the context is in `CTLS_HSHK_STATE_CONNECTED` and application traffic keys are derived.

### 4. Exchange application data

```c
static const uint8_t msg[] = "hello";
result = ctls_write(msg, sizeof(msg) - 1, CTLS_ENTITY_CLIENT);   // CTLS_ENTITY_SERVER on the server side

uint8_t wire_buf[CTLS_SIZE_WIRE_BUFFER];
uint8_t plaintext[CTLS_SIZE_WIRE_BUFFER];
result = ctls_read(wire_buf, plaintext, sizeof(plaintext), CTLS_ENTITY_CLIENT);  // entity of the SENDER you're reading from
```

`entity` always selects *whose* key material to use — pass your own role's entity to `ctls_write`, and the peer's entity to `ctls_read` (you're decrypting what *they* sent).

### 5. Close cleanly

```c
result = ctls_close(&ctx, CTLS_ENTITY_CLIENT);   // sends close_notify
close(my_socket);                                 // your transport teardown — the library doesn't own the socket
```

---

## Public API reference

Everything below is declared in `include/ctls/ctls.h` unless noted. `ctls_status_t` is `uint16_t`; `CTLS_STATUS_SUCCESS` is `0x0000`, everything else is a failure — see [Error handling](#error-handling).

### Lifecycle

#### `ctls_context_init`

```c
ctls_status_t ctls_context_init(ctls_context_t *context,
                                ctls_transport_t const *transport,
                                char const *template_path);
```

Zeroes the context, records `template_path`, loads and parses the profile from it, copies the transport callbacks, and runs crypto init (`psa_crypto_init`, transcript hash start). Must be called before `ctls_connect`/`ctls_accept`. Returns `CTLS_STATUS_SUCCESS`, `CTLS_STATUS_TMPL_PATH_NULL`, `CTLS_STATUS_TMPL_JSON_FILE_NOT_FOUND`, any `ctls_template_from_json` status, or a `CTLS_STATUS_CRYPTO_*` code.

#### `ctls_template_path_set`

```c
ctls_status_t ctls_template_path_set(ctls_context_t *context, char const *path);
```

Writes `path` into `context->template_path`. Called internally by `ctls_context_init` — you don't normally need to call this yourself. Returns `CTLS_STATUS_TMPL_PATH_NULL` if `path` is `NULL`.

### Handshake

#### `ctls_connect`

```c
ctls_status_t ctls_connect(ctls_context_t *context);
```

Client-side handshake: ClientHello → ServerHello → key schedule → server flight → client flight → application keys. Blocks on transport I/O. Returns `CTLS_STATUS_SUCCESS` on `CTLS_HSHK_STATE_CONNECTED`, or the first error from any step.

#### `ctls_accept`

```c
ctls_status_t ctls_accept(ctls_context_t *context);
```

Server-side mirror of `ctls_connect`.

### Application data

#### `ctls_write`

```c
ctls_status_t ctls_write(uint8_t const *application_data,
                         ctls_size_t application_data_length,
                         ctls_entity_t entity);
```

AEAD-encrypts and sends one application-data record. `entity` = your own role. Consumes one sequence number on success.

#### `ctls_read`

```c
ctls_status_t ctls_read(uint8_t *buffer,
                        uint8_t *application_data,
                        ctls_size_t application_data_length,
                        ctls_entity_t entity);
```

Receives and decrypts one application-data record. `buffer` is scratch space for the raw wire bytes (size it `CTLS_SIZE_WIRE_BUFFER`); `application_data` receives the decrypted plaintext. `entity` = the *sender's* role (i.e. whose read key to use). Returns `CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED` on a tag mismatch.

#### `ctls_send` / `ctls_receive` (advanced)

```c
ctls_status_t ctls_send(uint8_t *buffer, ctls_size_t length);
ctls_status_t ctls_receive(uint8_t *buffer, ctls_size_t *length, ctls_size_t capacity);
```

You won't normally call these — `ctls_connect`, `ctls_accept`, `ctls_read`, `ctls_write`, and `ctls_close` already route every wire record through them. They're the thin wrapper over your `ctls_transport_t` callbacks described in [Implement the transport callbacks](#1-implement-the-transport-callbacks): on `CTLS_DATAGRAM` builds they own the RFC 9147 §5.8 retransmit timer (stashing the last-sent record and retransmitting it on each `CTLS_STATUS_TRANSPORT_TIMEOUT`), and on `CTLS_STREAM` builds they pass through directly. Public mainly so custom protocol-level code (e.g. your own alert handling) can reuse the same timeout/retry behavior instead of calling `recd_send`/`recd_receive` directly.

### Shutdown

#### `ctls_close`

```c
ctls_status_t ctls_close(ctls_context_t *context, ctls_entity_t entity);
```

Sends an encrypted, WARNING-level `close_notify` alert (RFC 8446 §6.1) and moves the context to `CTLS_HSHK_STATE_CLOSED`. Does **not** close your transport/socket — that's still your job. Returns `CTLS_STATUS_SUCCESS` once the alert is sent (not `CTLS_STATUS_ALERT_CLOSE_NOTIFY` — that value means "sent OK" internally, and is translated to success for you).

### Template / profile

#### `ctls_template_from_json` (`templates.h`)

```c
ctls_status_t ctls_template_from_json(uint8_t const *json,
                                      ctls_size_t json_length,
                                      ctls_template_t *tmpl);
```

Parses a profile JSON document (see [The profile](#the-profile-templatejson)) directly into `*tmpl`, via the vendored `jsmn` parser — zero heap allocation. `ctls_template_set` (below) is the usual caller; call this directly only if you're loading JSON from somewhere other than a file (e.g. an embedded string, flash, or a network fetch) and want to skip the `fopen`.

#### `ctls_template_set` (`templates.h`)

```c
ctls_status_t ctls_template_set(ctls_context_t *context);
```

Opens `context->template_path`, reads it, and calls `ctls_template_from_json` into internal storage, then points `context->template` at it. Called internally by `ctls_context_init`.

#### `ctls_validate_template`

```c
ctls_status_t ctls_validate_template();
```

Checks the active template has `profile_id`, `protocol_version` (must be TLS 1.3), `cipher_suite`, `dhe_group`, `signature_algorithm`, and at least one `known_certificates` entry all set to real (non-zero) values. Called internally after `ctls_context_init`; returns the first `CTLS_STATUS_TMPL_INVALID_*` it finds.

### Accessors

These return pointers into the singleton context — used internally by every subsystem, exposed publicly in case you need direct access (e.g. from a custom hook or diagnostic code). Never free or replace the returned pointer.

```c
ctls_template_t const *ctls_template_get(void);
ctls_hshk_data_t      *ctls_hshk_data_get(void);
ctls_crypto_t         *ctls_crypto_get(void);
ctls_hshk_buffer_t    *ctls_hshk_buffer_get(void);
ctls_transport_t      *ctls_transport_get(void);
ctls_record_t         *ctls_record_get(void);
```

### Alerts (advanced)

You won't normally call these directly — they're what `ctls_connect`/`ctls_accept`/`ctls_close` use internally — but they're public if you're writing custom protocol-level error handling.

#### `ctls_status_to_alert_type_map`

```c
ctls_status_t ctls_status_to_alert_type_map(ctls_status_t status,
                                            ctls_hsmg_alert_type_t *alert_type,
                                            ctls_hsmg_alert_level_t *alert_level);
```

Maps any `ctls_status_t` to its RFC 8446 §6.2 alert type/level. The `CTLS_STATUS_ALERT_*` band (`types.h`, `0x0226`–`0x0240`) maps 1:1; everything else maps to the closest category, defaulting to `internal_error`.

#### `ctls_alert_send`

```c
ctls_status_t ctls_alert_send(ctls_record_t *record,
                              ctls_status_t status,
                              ctls_entity_t entity,
                              ctls_phase_t phase);
```

Maps `status` to an alert, builds and sends it, and returns `status` unchanged on success (this is why `ctls_close` doesn't call it directly and return the result as-is — see its doc above).

### Miscellaneous

```c
ctls_status_t ctls_handshake_state_update(ctls_hshk_state_t *location, ctls_hshk_state_t state);
ctls_status_t ctls_wire_buffer_clear(uint8_t *buffer, ctls_size_t *buffer_offest);
```

Internal helpers exposed for completeness — state-machine transition validation and scratch-buffer reset. Not something typical integration code needs to call.

---

## Error handling

Every function returns `ctls_status_t` (a `uint16_t`). `0x0000` is `CTLS_STATUS_SUCCESS`; every other value is a failure, range-partitioned by subsystem so you can tell where an error came from just from its numeric range:

| Range | Subsystem |
|---|---|
| `0x0001–0x0031` | General / parameter |
| `0x0032–0x0063` | Buffer / memory (incl. `CTLS_STATUS_BOUNDS_EXCEEDED`) |
| `0x0064–0x00C7` | Crypto (PSA-backed) |
| `0x00C8–0x012B` | Extension serialize/deserialize |
| `0x012C–0x015D` | Record layer |
| `0x015E–0x018F` | Handshake messages |
| `0x0190–0x01C1` | Template / profile |
| `0x01C2–0x01F3` | Transport |
| `0x01F4–0x0225` | Handshake state machine |
| `0x0226–0x0240` | Alert mapping (RFC 8446 §6.2 alert types) |

Full per-code listing: [`error-codes.md`](error-codes.md). Codes an integrator is most likely to see directly:

| Code | Meaning |
|---|---|
| `CTLS_STATUS_TMPL_PATH_NULL` | `ctls_context_init`/`ctls_template_path_set` got a `NULL` path. |
| `CTLS_STATUS_TMPL_JSON_FILE_NOT_FOUND` | The profile file couldn't be opened. |
| `CTLS_STATUS_TMPL_JSON_FIELD_MISSING` | A mandatory profile field is absent from the JSON. |
| `CTLS_STATUS_TMPL_JSON_UNKNOWN_ENUM_NAME` | A name string (cipher suite, group, scheme, extension) didn't match any known value — check spelling against the [field reference](#field-reference). |
| `CTLS_STATUS_TMPL_INVALID_*` | `ctls_validate_template` rejected the loaded profile — some mandatory field is still zero after parsing. |
| `CTLS_STATUS_TRANSPORT_SEND_FAILED` / `_RECV_FAILED` | Your transport callback returned failure. |
| `CTLS_STATUS_TRANSPORT_TIMEOUT` | `CTLS_DATAGRAM` only: `ctls_receive` exhausted the RFC 9147 §5.8 retransmit timer (up to `CTLS_DTLS_RETRANSMIT_TIMEOUT_MAX_MS`) with no response — the peer is unreachable or not responding. |
| `CTLS_STATUS_CRYPTO_AEAD_DECRYPT_FAILED` | AEAD tag mismatch on `ctls_read` — corrupted data, wrong keys, or an out-of-sync sequence number. |

---

## Constants reference

Compile-time constants from `config.h` you may need to know about (not typically things you'd override, but useful for sizing buffers):

| Constant | Value | Meaning |
|---|---|---|
| `CTLS_SIZE_WIRE_BUFFER` | 256 | Max size of one wire record — size your `ctls_read` scratch buffer to this. |
| `CTLS_TEMPLATE_JSON_PATH` | `"template.json"` | Convenience default path constant; not enforced — pass your own to `ctls_context_init`. |
| `CTLS_SIZE_JSON_BUFFER` | 4096 | Max profile JSON file size `ctls_template_set` will read. |
| `CTLS_SIZE_JSON_TOKENS` | 96 | Max jsmn tokens the profile JSON may parse into — increase if you add many extensions/certificates. |
| `CTLS_SIZE_KNOWN_CERTIFICATE_MAX` | 700 | Max DER length (bytes) per `knownCertificates` entry. |
| `CTLS_COUNT_KNOWN_CERTIFICATES` | 2 | Max number of `knownCertificates` entries. |
| `CTLS_PROFILE_ID` | `0x01` | Unused by the runtime path today (kept for reference — the JSON's own `profile` field is authoritative). |
| `CTLS_DTLS_RETRANSMIT_TIMEOUT_INITIAL_MS` | 1000 | `CTLS_DATAGRAM` only: initial `ctls_receive` wait before the first retransmit (RFC 9147 §5.8.2). |
| `CTLS_DTLS_RETRANSMIT_TIMEOUT_MAX_MS` | 60000 | `CTLS_DATAGRAM` only: cap on the doubling retransmit timer; `ctls_receive` gives up with `CTLS_STATUS_TRANSPORT_TIMEOUT` once reached. |

---

## Known limitations

This implementation targets one baseline profile (no PSK/0-RTT, single hardcoded signature algorithm, no HelloRetryRequest/KeyUpdate) and makes several project-specific design calls where the draft is silent or where DTLS 1.3/TLS 1.3 requirements weren't clearly inherited. Full detail, RFC citations, and rationale: [`ambiguities.md`](ambiguities.md).