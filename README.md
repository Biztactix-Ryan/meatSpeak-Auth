# MeatSpeak Auth

Authentication and identity library for the MeatSpeak IRC platform.

## Overview

MeatSpeak uses a decentralized identity layer that replaces traditional server accounts. Instead of registering a username and password on each server, users generate an Ed25519 keypair and publish their public key as a DNS TXT record. That keypair *is* their identity — it works across any meatSpeak server without federation or central authority. Servers authenticate users (and users authenticate servers) via mutual Ed25519 challenge-response. An optional SSO layer can issue short-lived JWTs for convenience, but it's not required and can be replaced without losing any user identities.

## What's Included

### Identity Library (`MeatSpeak.Identity`)

A complete implementation of the [Identity Spec v0.4](specs/IDENTITY-SPEC.md).

#### Cryptography (`Crypto/`)

- **`IdentityKeyPair`** — Ed25519 keypair wrapper built on libsodium. Generates keypairs, signs messages, verifies signatures. Zeroes private key memory on disposal to prevent leaks.

- **`KeyEncryption`** — Password-protected private key backup for SSO storage. Derives a 256-bit encryption key from the user's password using Argon2id (256 MB memory, 3 iterations) and encrypts the private key with AES-256-GCM. Automatically detects AES-NI hardware support and falls back to XChaCha20-Poly1305 on platforms without it. A version byte in the blob differentiates the encryption mode so decryption just works regardless of what encrypted it.

- **`ColdBackup`** — BIP38-style printable recovery strings for offline identity recovery. Produces a human-readable string like `idk1-7Ghx9mRk4Qp2Vn8Lw3Jt...` that encodes the encrypted private key, Argon2 parameters, and a salt into a Base58Check payload with a double-SHA256 checksum. A user can print this string on paper and recover their full identity from any device with just the string and their passphrase — no server needed.

#### DNS Records (`Records/` + `Dns/`)

- **`RecordParser`** — Parses semicolon-delimited DNS TXT record strings into typed objects. Handles Base64URL decoding, optional fields with defaults, key flag parsing (`primary`, `rotate`, `revoked`), entity type detection, and validation of required fields.

- **`RecordBuilder`** — The inverse: builds DNS TXT record strings from structured objects. Includes handle normalization (lowercasing, `#` to `--`, stripping non-alphanumeric characters) for the `_h` handle mapping records.

- **Record types:**
  - **`KeyRecord`** — Entity public keys published at `<uid>._k.<domain>`. Carries the algorithm, key ID, Base64URL-encoded public key, optional expiry, key flags, and entity type.
  - **`IdpRecord`** — Identity provider discovery at `_idp.<domain>`. Points to the SSO issuer URL and JWKS endpoint.
  - **`HandleRecord`** — Human-readable handle to UID mapping at `<handle>._h.<domain>`.
  - **`MigrationRecord`** — Domain migration pointers at `<uid>._m.<domain>`. Includes a cryptographic signature proving the migration was authorized by the key holder, not the domain operator.

#### Identity Resolution (`Resolution/`)

Three resolvers implementing a common `IIdentityResolver` interface with five resolution operations (keys, server keys, handles, IDP discovery, migration records):

- **`DnsIdentityResolver`** — Primary resolver. Uses DnsClient.NET to query DNS TXT records. Constructs the correct DNS labels (`{uid}._k.{domain}`, `_k.{serverDomain}`, `{handle}._h.{domain}`, `_idp.{domain}`, `{uid}._m.{domain}`). Gracefully skips malformed records without failing the entire lookup.

- **`HttpsIdentityResolver`** — Fallback for networks that block DNS lookups. Queries HTTPS endpoints (`/k/{uid}`, `/h/{handle}`, `/.well-known/jwks.json`) served by the identity provider.

- **`FallbackResolver`** — Composite resolver that tries DNS first and falls back to HTTPS. Default constructor wires up both automatically.

#### Trust & TOFU (`Trust/`)

SSH-style trust-on-first-use key pinning:

- **`TofuVerifier`** — On first contact with an entity, computes a BLAKE2b fingerprint of its public key and pins it. On subsequent contacts, verifies the fingerprint matches. Returns `TrustedFirstUse`, `TrustedPinMatch`, or `KeyChanged` (which triggers a warning, just like SSH's "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED").

- **`FileTofuStore`** — Persistent JSON-based pin storage (like `~/.ssh/known_hosts`). Stores entity ID, key fingerprint, first-seen timestamp, and which DNS sources confirmed the key. Thread-safe via semaphore.

#### Dual-Source Verification (`Verification/`)

- **`DualSourceVerifier`** — The core trust mechanism for servers. When a client connects to a server, it resolves the server's public key from two independent DNS zones:
  1. The shared identity domain (`<server-uid>._k.id.example.org`)
  2. The server's own domain (`_k.chat.example.org`)

  If both sources return the same key, confidence is high (`Verified`). If only one source is available, the result is `Partial`. If the keys disagree, the result is `KeyMismatch` — meaning either a misconfiguration or a compromise. Revoked keys are automatically filtered out.

#### Mutual Authentication (`Auth/`)

Ed25519 challenge-response handshake where both sides prove identity:

- **`MutualAuth`** — Implements the full handshake protocol:
  1. **ServerHello**: Server generates a 16-byte random nonce, signs `(nonce_s | timestamp)` with its Ed25519 key, and sends the signed hello to the client.
  2. **ClientHello**: Client verifies the server's signature via DNS dual-source lookup, then generates its own nonce and signs `(nonce_s | nonce_c | server_uid | timestamp)` — binding the response to the specific server and its nonce to prevent replay and relay attacks.
  3. Timestamps must be within 5 minutes to prevent replay of old handshakes.

- **`ServerHello` / `ClientHello`** — Immutable message records carrying the UID, key ID, nonce, timestamp, and Ed25519 signature.

#### UIDs

- **`Uid`** — ULID-based identifiers (Crockford Base32, 26 characters). Timestamp-ordered, collision-resistant, DNS-label-safe. Case-insensitive with lowercase normalization. Supports timestamp extraction for rough age-of-account signals.

## Project Structure

```
src/
  MeatSpeak.Identity/
    Auth/                    # Mutual authentication handshake
    Crypto/                  # Ed25519 keypairs, key encryption, cold backup
    Dns/                     # DNS TXT record builder
    Records/                 # DNS record models and parser
    Resolution/              # Identity resolution (DNS, HTTPS, fallback)
    Trust/                   # TOFU key pinning
    Verification/            # Dual-source server verification
    EntityType.cs
    Uid.cs
tests/
  MeatSpeak.Identity.Tests/  # xUnit + NSubstitute
specs/
  IDENTITY-SPEC.md           # Core identity spec (v0.4)
  DNS-RECORDS-SPEC.md        # DNS record reference (v0.4)
  RECOVERY-SPEC.md           # Recovery & account lifecycle (v0.4)
  VOICE-SPEC.md              # Voice extension spec (v0.1)
```

## Requirements

- [.NET 9.0](https://dotnet.microsoft.com/download/dotnet/9.0)

## Build

```bash
dotnet build MeatSpeak.Identity.sln
```

## Test

```bash
dotnet test MeatSpeak.Identity.sln
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [Ulid](https://github.com/Cysharp/Ulid) | ULID generation and parsing |
| [Sodium.Core](https://github.com/tabrath/libsodium-core) | Ed25519, XChaCha20-Poly1305, Argon2id, BLAKE2b |
| [DnsClient](https://github.com/MichaCo/DnsClient.NET) | DNS TXT record resolution |
| [SimpleBase](https://github.com/ssg/SimpleBase) | Base58Check encoding for cold backup keys |
| [System.IdentityModel.Tokens.Jwt](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | JWT handling for SSO integration |

## Specs

### Identity Specifications (v0.4)

The identity system is documented across three focused specs:

#### [Core Identity Specification](specs/IDENTITY-SPEC.md)

Start here. Defines how identity works day-to-day: entities, UIDs, key hierarchy, dual-source DNS verification, mutual authentication, SSO integration, and registration flows.

#### [DNS Record Reference](specs/DNS-RECORDS-SPEC.md)

Keep this open while coding. Normative reference for all DNS record types: field tables, encoding rules, TXT record conventions, TTL strategy, HTTPS fallback endpoints with JSON formats, and complete zone file examples.

#### [Recovery & Account Lifecycle](specs/RECOVERY-SPEC.md)

What happens when things go wrong. Four-layer key recovery model, recovery contacts, account state model, and detailed scenarios for root key rotation, full recovery, and social death — each with step-by-step flows, edge cases, and security analysis.

#### [Voice Extension](specs/VOICE-SPEC.md) (v0.1)

SFU voice over IRC — Opus codec, XChaCha20-Poly1305 transport encryption, optional E2E encryption with group key rotation, spatial audio, whisper/priority speakers, stage channels.

### Workflow Diagrams

#### Device Enrollment

Detailed steps: see [IDENTITY-SPEC.md §2.3](specs/IDENTITY-SPEC.md) and [DNS-RECORDS-SPEC.md §3.7](specs/DNS-RECORDS-SPEC.md)

```
User (has root key)              Identity Server
  |                                    |
  | Generate device keypair            |
  | Sign enrollment with root key      |
  |                                    |
  | Send: uid, device_pk, enroll_sig   |
  |----------------------------------->|
  |                                    |
  |    Verify enroll_sig against       |
  |    root key in DNS                 |
  |                                    |
  |    Publish device key TXT record   |
  |                                    |
  | OK                                 |
  |<-----------------------------------|
```

#### Device Revocation (lost/stolen device)

Detailed steps: see [IDENTITY-SPEC.md §2.4](specs/IDENTITY-SPEC.md)

```
User (has root key)              Identity Server
  |                                    |
  | Sign revocation for device_kid     |
  | with root key                      |
  |                                    |
  | Send: uid, device_kid, revoke_sig  |
  |----------------------------------->|
  |                                    |
  |    Verify revoke_sig against       |
  |    root key in DNS                 |
  |                                    |
  |    Set flag=revoked on device key  |
  |                                    |
  | OK                                 |
  |<-----------------------------------|
```

#### Root Key Rotation (lost root key, has working devices)

Detailed steps: see [RECOVERY-SPEC.md §5](specs/RECOVERY-SPEC.md)

```
Ryan (device key)        Tara (recovery contact)     Identity Server
  |                           |                            |
  | "I need root rotation"    |                            |
  | signed with device key    |                            |
  |-------------------------------------------------------->|
  |                           |                            |
  |                           | Confirm rotation           |
  |                           | signed with her key        |
  |                           |--------------------------->|
  |                           |                            |
  |                     State: ROOT_ROTATION               |
  |                     14-day waiting period               |
  |                     (cancelable by any device key)      |
  |                           |                            |
  |  ... 14 days pass ...     |                            |
  |                           |                            |
  | Generate new root key     |                            |
  | Tara signs authorization  |                            |
  |-------------------------------------------------------->|
  |                           |                            |
  |                     Old root revoked                   |
  |                     New root published                 |
  |                     Device keys unchanged              |
```

#### Full Recovery (lost everything)

Detailed steps: see [RECOVERY-SPEC.md §6](specs/RECOVERY-SPEC.md)

```
Ryan (no keys)           Tara (recovery contact)     Identity Server
  |                           |                            |
  | (out-of-band: "help!")    |                            |
  |  ~~~~phone call~~~~>      |                            |
  |                           |                            |
  |                           | Initiate full recovery     |
  |                           | signed with her key        |
  |                           |--------------------------->|
  |                           |                            |
  |                     State: FULL_RECOVERY               |
  |                     All device keys: contested         |
  |                     14-day waiting period               |
  |                     (cancelable by root key ONLY)       |
  |                           |                            |
  |  ... 14 days pass ...     |                            |
  |                           |                            |
  | Generate new root key     |                            |
  | + first device key        |                            |
  | Tara signs authorization  |                            |
  |-------------------------------------------------------->|
  |                           |                            |
  |                     All old keys revoked               |
  |                     New root + device published        |
```

#### Recovery Contact Change

Detailed steps: see [RECOVERY-SPEC.md §3.3-3.4](specs/RECOVERY-SPEC.md)

```
User (root key)          Old Contact       New Contact     Identity Server
  |                          |                 |                 |
  | Sign rc_change           |                 |                 |
  | with root key            |                 |                 |
  |----------------------------------------------------->------->|
  |                          |                 |                 |
  |                     State: RC_CHANGE_PENDING                 |
  |                     7-day waiting period                      |
  |                          |                 |                 |
  |                 Notified |        Notified |                 |
  |                     <----|           <-----|                 |
  |                          |                 |                 |
  |  (cancelable by any device key or root key)                  |
  |                          |                 |                 |
  |  ... 7 days pass ...     |                 |                 |
  |                          |                 |                 |
  |                     Old contact removed                      |
  |                     New contact active                       |
```

#### Social Death

Detailed steps: see [RECOVERY-SPEC.md §7](specs/RECOVERY-SPEC.md)

```
                         Tara (recovery contact)     Identity Server
                              |                            |
                              | Initiate death declaration |
                              | signed with her key        |
                              |--------------------------->|
                              |                            |
                        State: DEATH                       |
                        60-day grace period                 |
                        Sessions continue                  |
                        (cancelable by root key             |
                         or ANY device key)                 |
                              |                            |
  ... 60 days, no cancellation ...                         |
                              |                            |
                        State: TOMBSTONE                   |
                        All keys revoked                   |
                        UID permanently burned             |
                        Can never be re-enabled            |
```

## Related Repositories

- [meatSpeak-server](https://github.com/Biztactix-Ryan/meatSpeak-server) — Server implementation
- [meatSpeak-client](https://github.com/Biztactix-Ryan/meatSpeak-client) — Client application

## License

TBD
