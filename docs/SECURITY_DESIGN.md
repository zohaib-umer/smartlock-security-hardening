# Record security design

This guide describes the implementation in [`securelink2.cpp`](../securelink2.cpp). The course-provided handshake and application state machine are separate dependencies.

## Record format

| Field | Length | Purpose |
| --- | --- | --- |
| Sequence | 8 bytes | Unsigned big-endian sequence number; also authenticated as GCM additional data |
| Ciphertext | Plaintext length | AES-GCM encrypted payload |
| Tag | 16 bytes | Authentication tag |

A binary record adds 24 bytes before the surrounding text protocol hex-encodes it. The nonce is reconstructed from the sequence rather than transmitted in this record.

## Key derivation

`derive_key(shared_secret, suite, context)` uses HKDF-SHA256 with the fixed protocol salt `SmartLock-v2-HKDF-SHA256`. Its information field is `SmartLock-v2|<suite>|<context>`.

AES256-GCM derives 32 bytes; AES128-GCM derives 16 bytes. The caller supplies `c2s` and `s2c` contexts for distinct directional keys. This function is deterministic: a fresh session secret must come from the handshake.

## Nonce construction

`make_nonce(seqno)` returns four zero bytes followed by the eight-byte big-endian sequence. Different sequence numbers produce different nonces, but repeating a sequence with the same key repeats a nonce.

The application must keep independent send/receive state, never reset a sequence under an existing key, and establish a fresh key before the counter wraps. The cryptographic module does not maintain counters itself.

## Receive path

1. Validate the AES key length and minimum record length.
2. Compare the received sequence with the caller's expected sequence.
3. Reconstruct the nonce and authenticate the sequence as additional data.
4. Decrypt and verify the authentication tag.
5. Return plaintext only after successful authentication.

The caller advances its expected sequence only after success. Unexpected sequences, invalid tags, and malformed records raise exceptions.

## Boundaries

Certificate checks and signed DH transcripts are scaffold responsibilities. The legacy pairing digest remains outside this module's protection. The [main README](../README.md) and [handshake diagram](../evidence/SmartLock_v2_Handshake_PartB.png) identify the proposed, unimplemented PIN redesign.

The [core self-check source](../evidence/23i-0528-F-TASKC-V1.cpp) exercises the record API; [archived results](../evidence/C_A4_aead_test.txt) are provided for review.
