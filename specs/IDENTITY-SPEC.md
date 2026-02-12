# DNS-First Identity Layer — Core Specification v0.4

**Status:** Draft
**Goal:** A decentralized, low-cost identity system for open-source communities using DNS as the public directory and Ed25519 signatures for verification. No always-on central infrastructure required.

**Companion Documents:**
- [DNS-RECORDS-SPEC.md](DNS-RECORDS-SPEC.md) — Normative reference for all DNS record types, field tables, encoding rules, zone file examples
- [RECOVERY-SPEC.md](RECOVERY-SPEC.md) — Recovery contacts, account state model, recovery scenarios, key storage layers

**Changes from v0.3:** Split monolithic spec into three focused documents. Core spec retains day-to-day identity operations. Recovery scenarios expanded with edge cases and UX guidance (see RECOVERY-SPEC). DNS record formats expanded with full field tables, zone file examples, and HTTPS JSON formats (see DNS-RECORDS-SPEC).

**Changes from v0.2:** Added root key / device key hierarchy, device management, recovery contacts, social recovery, social death, account state model.

**Changes from v0.1:** Added server identity as first-class concept, mutual authentication, dual-source DNS verification, SSO challenge-response flow, encrypted key backup, BIP38-style cold recovery keys.

---

## 1. Core Concepts

### 1.1 Entities

The system treats three entity types identically at the cryptographic layer:

| Entity              | Has UID | Has Keypair | Publishes to DNS | Issues Tokens |
|---------------------|---------|-------------|-------------------|---------------|
| User                | Yes     | Yes         | Via identity domain | No           |
| Server              | Yes     | Yes         | Via identity domain AND own domain | No |
| Identity Provider   | Yes     | Yes         | Via `_idp` record + JWKS | Yes (JWTs) |

All entities use the same UID format, key format, DNS layout, and verification flow.

### 1.2 UID Format

**Format:** ULID (Universally Unique Lexicographically Sortable Identifier)
**Encoding:** Crockford Base32, 26 characters
**Example:** `01j5a3k7pm9qwr4txyz6bn8vhe`

**Why ULID:**
- Timestamp-ordered (debugging, rough age-of-account signals)
- No coordination needed to generate
- URL-safe, DNS-label-safe (lowercase alphanumeric)
- 128-bit, collision-resistant

**Normalization:** UIDs MUST be lowercased in DNS labels. Implementations MUST treat UIDs case-insensitively.

### 1.3 Design Principles

1. **DNS publishes truthy public material; everything else is optional.**
2. **Identity is a keypair, not a server account.** Servers are convenience infrastructure.
3. **Mutual authentication.** Users verify servers, servers verify users, using the same protocol.
4. **Dual-source verification.** Servers publish keys in their own DNS as an independent trust anchor.
5. **Hierarchical key authority.** Root key is the identity anchor; device keys are scoped to individual machines.
6. **Graceful degradation.** Each trust layer is additive, not required.

---

## 2. Key Hierarchy

### 2.1 Root Key

- Generated at registration from Ed25519 keypair (derived from BIP-39 seed)
- Published in DNS with `flag=root`
- NEVER used for authentication — only signs:
  - Device enrollments
  - Device revocations
  - Recovery contact designations
  - Recovery contact changes
  - Migration statements
- Cold backup (BIP38-style string) encodes this root private key — see [RECOVERY-SPEC.md §2.4](RECOVERY-SPEC.md#24-layer-3--cold-backup-key-bip38-style)
- One root key per UID at any time

### 2.2 Device Keys

- Per-device Ed25519 keypairs, published in DNS with `device=<name>` and `enroll_sig=<sig>`
- Used for all authentication (mutual auth, SSO challenge-response, etc.)
- Each device key is independently revocable without affecting other devices
- Clients performing authentication use device keys, never root key

### 2.3 Device Enrollment

- Requires root key signature: `Sign(root_key, "enroll"|uid|device_kid|device_pk|timestamp)`
- Published as a new TXT record with the enrollment signature embedded
- Identity server verifies enrollment signature against the published root key before accepting
- See [DNS-RECORDS-SPEC.md §3.7](DNS-RECORDS-SPEC.md#37-enrollment-signature-verification) for verification pseudocode

### 2.4 Device Revocation

- Requires root key signature: `Sign(root_key, "revoke"|uid|device_kid|timestamp)`
- Revoked device key gets `flag=revoked` in DNS
- Relying parties MUST reject revoked device keys immediately
- Does NOT require the device itself — solves lost/stolen device problem

### 2.5 Key Hierarchy Diagram

```
Root Key (offline, flag=root, from BIP-39 seed)
  |
  +-- Signs --> Device Key: "ryan-desktop" (daily auth)
  +-- Signs --> Device Key: "ryan-phone" (daily auth)
  +-- Signs --> Device Key: "ryan-laptop" (daily auth)
  |
  +-- Signs --> Recovery contact designations
  +-- Signs --> Recovery contact changes
  +-- Signs --> Domain migration statements
```

---

## 3. DNS Record Layout

All identity records live under a configurable **identity domain**, e.g. `id.example.org`. The table below summarizes all record types. See [DNS-RECORDS-SPEC.md](DNS-RECORDS-SPEC.md) for full field tables, encoding rules, examples, and zone file snippets.

| Record Type | DNS Label | Purpose | Key Fields |
|-------------|-----------|---------|------------|
| Identity Provider | `_idp.<domain>` | Discover SSO issuer and JWKS | `issuer`, `jwks` |
| Entity Key | `<uid>._k.<domain>` | Publish root and device keys | `k`, `kid`, `pk`, `flag`, `device`, `enroll_sig` |
| Server Self-Key | `_k.<server-domain>` | Dual-source trust anchor | `k`, `kid`, `pk`, `uid` |
| Handle | `<handle>._h.<domain>` | Map human name to UID | `uid` |
| Migration | `<uid>._m.<domain>` | Redirect to new identity domain | `to`, `ts`, `sig` |
| Recovery Contact | `<uid>._rc.<domain>` | Designate social recovery contact | `rc`, `sig`, `window` |
| RC Change | `<uid>._rcc.<domain>` | Pending recovery contact change | `old_rc`, `new_rc`, `effective`, `sig` |
| Account State | `<uid>._s.<domain>` | Signal non-stable account state | `state`, `by`, `ts`, `expires` |

**Total DNS records per user: 2-5 TXT** (root key + device key(s) + optional recovery contact + optional state). **Per server: 2-3 TXT.**

---

## 4. Dual-Source DNS Verification

When a client connects to a server, it can verify the server's identity against two independent DNS sources.

### 4.1 Verification Flow

```
Client connects to chat.devreg.org
  |
  +- Source 1: Identity domain
  |   Resolve <server-uid>._k.id.example.org -> public key A
  |
  +- Source 2: Server's own domain
  |   Resolve _k.chat.devreg.org -> public key B
  |
  +- Compare:
       +- A == B  -> High confidence (two independent zones agree)
       +- A only  -> Acceptable (server hasn't set up self-publishing)
       +- B only  -> Acceptable (server isn't in a central identity domain)
       +- A != B  -> WARN USER -- possible compromise or misconfiguration
```

### 4.2 Trust Modes

Clients SHOULD support configurable trust levels:

| Mode     | Requirement                     | Use Case                    |
|----------|---------------------------------|-----------------------------|
| Relaxed  | Either source sufficient        | Casual use, one zone down   |
| Standard | At least one source + TOFU pin  | Default for most users      |
| Strict   | Both sources must agree         | High-trust communities      |

### 4.3 TOFU (Trust On First Use)

On first connection, clients SHOULD pin:
- Server UID
- Public key fingerprint
- Which sources confirmed it

On subsequent connections, clients MUST warn if:
- Key has changed without a `rotate` flag on the old key
- Sources that previously agreed now disagree
- Key fingerprint doesn't match pin

This is the SSH `known_hosts` model applied to community servers.

---

## 5. Mutual Authentication

### 5.1 Handshake

After TLS is established, both sides prove identity using the same Ed25519 challenge-response. **Users authenticate with device keys, not root keys.** Servers verify device key signatures against DNS records that include the enrollment signature chain.

```
      Server                                        Client
        |                                              |
  [1]   |  ServerHello                                 |
        |  { server_uid, kid, nonce_s }                |
        |  + sig = Sign(server_key, nonce_s|timestamp) |
        |--------------------------------------------->|
        |                                              |
        |              Client verifies server sig      |
        |              via DNS dual-source lookup       |
        |              Checks TOFU pin                  |
        |                                              |
  [2]   |                            ClientHello       |
        |  { user_uid, kid, nonce_c }                  |
        |  + sig = Sign(device_key, nonce_s|nonce_c|   |
        |          server_uid|timestamp)               |
        |<---------------------------------------------|
        |                                              |
        |  Server verifies device key sig              |
        |  via DNS lookup (checks enroll_sig chain)    |
        |                                              |
  [3]   |  SessionEstablished                          |
        |  { session_token, expires }                  |
        |--------------------------------------------->|
        |                                              |
        |  === Mutual trust established ===            |
```

**Requirements:**
- Both nonces MUST include >=16 random bytes.
- Client signature MUST bind to server_uid and server nonce to prevent replay and relay attacks.
- Timestamps MUST be within 5 minutes.
- All signatures use Ed25519 over the canonical byte representation.
- Client MUST use a device key, never the root key, for authentication signatures.

### 5.2 Anonymous / Lightweight Connection

Not every connection requires mutual auth. Servers MAY support:

- **Server-verified only:** Client verifies server identity but connects anonymously.
- **Token-based:** Client presents a JWT from the SSO instead of doing direct key auth. Useful when the client doesn't want to expose its UID to every server.

---

## 6. SSO Integration

The SSO/Identity Provider is a convenience layer. It issues short-lived tokens so users don't need to perform challenge-response with every individual server.

### 6.1 SSO Authentication Flow

Users authenticate to the SSO using their **device key** (not root key):

```
User                        SSO                         Game Server
 |                           |                                |
 |  "I am <uid>"             |                                |
 |-------------------------->|                                |
 |                           |                                |
 |  challenge (nonce)        |                                |
 |<--------------------------|                                |
 |                           |                                |
 |  Sign(device_key, nonce)  |                                |
 |-------------------------->|                                |
 |                           |                                |
 |    SSO resolves UID keys from DNS                          |
 |    SSO verifies device key signature                       |
 |    (checks enroll_sig against root key)                    |
 |                           |                                |
 |  JWT { uid, exp, aud }    |                                |
 |  signed by SSO's key      |                                |
 |<--------------------------|                                |
 |                           |                                |
 |  Present JWT              |                                |
 |---------------------------------------------------------->|
 |                           |                                |
 |                           |   Verify SSO sig via           |
 |                           |   _idp DNS record + JWKS       |
```

### 6.2 SSO Properties

The SSO is **stateless with respect to identity**:
- Does NOT store passwords (keys are user-held)
- Does NOT own the user's identity
- Does NOT need to be always-online (direct mutual auth still works)
- CAN be replaced without losing any user identities
- CAN be run by any community member who publishes an `_idp` record

### 6.3 JWT Claims

```json
{
  "iss": "https://id.example.org",
  "sub": "<user-uid>",
  "aud": "<server-uid or wildcard>",
  "iat": 1738540800,
  "exp": 1738541100,
  "kid": "<user-key-id>",
  "jti": "<unique-token-id>"
}
```

**Token lifetime:** 5 minutes recommended. Short-lived tokens mean revocation is just "stop issuing new tokens."

---

## 7. Registration Flow

### 7.1 New User

```
1.  Client generates ULID -> uid
2.  Client generates root Ed25519 keypair (from BIP-39 seed) -> (root_private, root_public)
3.  Client generates first device Ed25519 keypair -> (device_private, device_public)
4.  Root key signs device enrollment:
      enroll_sig = Sign(root_key, "enroll"|uid|device_kid|device_pk|timestamp)
5.  Client generates cold backup string (encodes root private key)
      See RECOVERY-SPEC.md §2.4 for cold backup format
6.  Client derives encryption key from user's password via Argon2id
7.  Client encrypts device_private_key -> encrypted_blob
      See RECOVERY-SPEC.md §2.3 for encrypted backup format
8.  Client sends to SSO:
      { uid, root_public_key, device_public_key, enroll_sig, device_name,
        encrypted_blob, salt, argon2_params }
9.  SSO publishes to DNS:
      Root key:   <uid>._k.<domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<root_pk>;flag=root"
      Device key: <uid>._k.<domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<device_pk>;device=<name>;enroll_sig=<sig>"
      See DNS-RECORDS-SPEC.md §3 for full record format
10. Client stores device private key in device keychain
11. Client prompts user to designate a recovery contact (optional but recommended)
      See RECOVERY-SPEC.md §3 for recovery contact setup
12. Done -- user never saw any cryptography
```

### 7.2 New Server

```
1.  Operator generates ULID -> server_uid
2.  Operator generates Ed25519 keypair
3.  Operator publishes to own DNS zone:
      _k.<server-domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<pk>;uid=<server_uid>"
      See DNS-RECORDS-SPEC.md §4 for server key format
4.  Operator registers with identity domain (optional):
      <server_uid>._k.<identity-domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<pk>;type=server"
5.  Operator stores private key securely + generates cold backup
```

---

## 8. HTTPS Fallback

Some networks block non-standard DNS lookups. The spec defines an HTTPS fallback serving identical data.

### Resolution Order

1. Try DNS (fast, cacheable, decentralized)
2. Fall back to HTTPS (reliable, CDN-friendly)
3. Check device cache / TOFU pins (works offline)

See [DNS-RECORDS-SPEC.md §11](DNS-RECORDS-SPEC.md#11-https-fallback-endpoints) for endpoint table and JSON response formats.

---

## 9. Security Considerations

These security considerations cover core operational threats. See [RECOVERY-SPEC.md §5-7](RECOVERY-SPEC.md) for recovery-specific threats and [DNS-RECORDS-SPEC.md §12](DNS-RECORDS-SPEC.md#12-security-considerations) for DNS-specific threats.

**DNS is not private.** Public keys are public. Do not store sensitive data in DNS.

**DNSSEC recommended** but not required. Without DNSSEC, network attackers could spoof DNS. The HTTPS fallback (TLS) and dual-source verification provide alternative trust paths.

**Dual-source verification** (§4) means compromising a server's identity requires compromising two independent DNS zones simultaneously.

**Revocation latency.** DNS caching delays revocation. Mitigation: short-lived JWTs (5-min expiry). "Revoke" = "stop issuing tokens" + wait for TTL. See [DNS-RECORDS-SPEC.md §10.3](DNS-RECORDS-SPEC.md#103-ttl-during-emergency-revocation) for TTL strategy.

**SSO compromise.** A compromised SSO can issue fraudulent JWTs but CANNOT steal private keys (encrypted blobs are opaque). Servers MAY require direct mutual auth for high-security actions.

**Enumeration.** UIDs are opaque. Handle mappings are enumerable — keep them opt-in.

**Root key compromise.** Worst case: attacker with the root key can enroll rogue devices and revoke legitimate ones. The recovery contact is the safety net — the real user can initiate recovery via their contact to regain control. The 7-day recovery contact change delay prevents a compromised root key from silently swapping the recovery contact.

**Recovery contact compromise.** A compromised recovery contact can initiate full recovery or social death. Grace periods (14d/60d) give the real user time to cancel. See [RECOVERY-SPEC.md §6.8](RECOVERY-SPEC.md#68-security-considerations) and [RECOVERY-SPEC.md §7.8](RECOVERY-SPEC.md#78-security-considerations) for detailed analysis.

---

## 10. Implementation Notes (.NET)

### Recommended Libraries

| Concern           | Library                                     |
|-------------------|---------------------------------------------|
| ULID generation   | `Cysharp/Ulid`                              |
| Ed25519           | `NSec.Cryptography` or `libsodium-net`      |
| Argon2id          | `Konscious.Security.Cryptography` or `libsodium-net` |
| AES-256-GCM       | `System.Security.Cryptography.AesGcm`       |
| DNS resolution    | `DnsClient.NET`                             |
| Base64url         | `Microsoft.IdentityModel.Tokens.Base64UrlEncoder` |
| Base58Check       | `SimpleBase` NuGet package                  |
| JWT               | `System.IdentityModel.Tokens.Jwt`           |
| JSON              | `System.Text.Json`                          |

### Minimal Verification (Pseudocode)

```csharp
async Task<VerifyResult> VerifyServer(string serverUid, string serverDomain,
                                       string identityDomain, byte[] challenge,
                                       string kid, byte[] signature)
{
    // Source 1: Identity domain
    var idKey = await ResolveKey($"{serverUid}._k.{identityDomain}");

    // Source 2: Server's own domain
    var selfKey = await ResolveKey($"_k.{serverDomain}");

    // Dual-source comparison
    if (idKey != null && selfKey != null && idKey.Pk != selfKey.Pk)
        return VerifyResult.KeyMismatch; // WARN USER

    // Verify signature against whichever key(s) we have
    var key = idKey ?? selfKey;
    if (key == null) return VerifyResult.NoKeyFound;

    return Ed25519.Verify(key.PublicKey, challenge, signature)
        ? VerifyResult.Verified
        : VerifyResult.SignatureFailed;
}
```

---

## 11. What This Spec Does NOT Cover (By Design)

Explicitly out of scope to keep ops costs near zero:

- Profiles, avatars, display names — optional HTTPS / plugins
- Discovery / friend search — invite codes, QR, optional directory servers
- OAuth / OIDC sessions — layer on top; this spec provides key material
- Private messaging key exchange — future extension (X25519)
- Payments, reputation, moderation — application-layer concerns
- Access control / permissions — server-side policy, not identity-layer

---

## Appendix A: Companion Document Map

| Document | What It Covers | When To Read |
|----------|---------------|--------------|
| **This document** (IDENTITY-SPEC) | Core identity model, key hierarchy, verification, authentication, SSO, registration | Start here. Understand how identity works day-to-day. |
| [DNS-RECORDS-SPEC.md](DNS-RECORDS-SPEC.md) | All DNS record types, field tables, encoding rules, TTL strategy, HTTPS fallback, zone file examples | Keep open while coding. Reference for record formats. |
| [RECOVERY-SPEC.md](RECOVERY-SPEC.md) | Recovery contacts, key storage layers, account state model, root key rotation, full recovery, social death, device key rotation lifecycle | Read when implementing recovery flows or understanding what happens when things go wrong. |

## Appendix B: Trust Verification Summary

```
                    +-------------------------------------+
                    |           User connects to           |
                    |          chat.devreg.org             |
                    +--------------+----------------------+
                                   |
                    +--------------v----------------------+
                    |     Server presents signed hello     |
                    |     { server_uid, kid, nonce, sig }  |
                    +--------------+----------------------+
                                   |
                 +-----------------+------------------+
                 v                                    v
    +------------------------+         +------------------------+
    |  DNS Source 1           |         |  DNS Source 2           |
    |  <uid>._k.id.example   |         |  _k.chat.devreg.org    |
    |  (identity domain)      |         |  (server's own domain)  |
    +-----------+------------+         +-----------+------------+
                |                                   |
                +-------------+--------------------|+
                              |
                 +------------v------------------+
                 |  Keys match?                   |
                 |  +- Both agree    -> Verified  |
                 |  +- One source    -> Partial   |
                 |  +- Disagree      -> Warn      |
                 +------------+------------------+
                              |
                 +------------v------------------+
                 |  TOFU check against pinned key |
                 |  +- Matches pin   -> Trusted   |
                 |  +- New key       -> Prompt    |
                 |  +- Changed key   -> Alert     |
                 +---------------------------------+
```
