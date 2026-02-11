# DNS-First Identity Layer — Minimal Spec v0.2

**Status:** Draft
**Goal:** A decentralized, low-cost identity system for open-source communities using DNS as the public directory and Ed25519 signatures for verification. No always-on central infrastructure required.

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
5. **Graceful degradation.** Each trust layer is additive, not required.

---

## 2. DNS Record Layout

All identity records live under a configurable **identity domain**, e.g. `id.example.org`.

### 2.1 Identity Provider Discovery

```
_idp.<domain>  TXT  "v=1;issuer=https://<domain>;jwks=/.well-known/jwks.json"
```

| Field    | Required | Description                                           |
|----------|----------|-------------------------------------------------------|
| `v`      | Yes      | Spec version. Currently `1`.                          |
| `issuer` | Yes      | Canonical HTTPS origin of the identity provider.      |
| `jwks`   | No       | Path to JWKS endpoint. Default: `/.well-known/jwks.json` |

### 2.2 Entity Keys (Users and Servers)

```
<uid>._k.<domain>  TXT  "v=1;k=<alg>;kid=<key-id>;pk=<base64url-pubkey>"
```

| Field  | Required | Description                                                    |
|--------|----------|----------------------------------------------------------------|
| `v`    | Yes      | Spec version. Currently `1`.                                   |
| `k`    | Yes      | Key algorithm. MUST be `ed25519`.                              |
| `kid`  | Yes      | Key identifier. Recommended: `YYYY-MM` or short slug.         |
| `pk`   | Yes      | Public key, Base64url-encoded (no padding).                    |
| `exp`  | No       | Expiry hint (ISO 8601 date). Advisory.                         |
| `flag` | No       | Comma-separated: `primary`, `rotate`, `revoked`.               |
| `type` | No       | Entity type: `user`, `server`, `idp`. Default: `user`.         |

Multiple keys are published as multiple TXT records on the same label.

### 2.3 Server Self-Published Keys (Dual-Source)

In addition to publishing in the identity domain, servers SHOULD publish their public key in their own DNS zone:

```
_k.<server-domain>  TXT  "v=1;k=ed25519;kid=<key-id>;pk=<base64url>;uid=<server-uid>"
```

**Example:**
```
# Identity domain (operated by identity community)
01j5srv7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=2026-02;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;type=server"

# Server's own domain (operated by server owner)
_k.chat.devreg.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=2026-02;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;uid=01j5srv7pm9qwr4txyz6bn8vhe"
```

Same key, two zones, two operators. Both must agree.

### 2.4 Handle Mapping (Optional)

```
<normalized-handle>._h.<domain>  TXT  "v=1;uid=<uid>"
```

Handle normalization: lowercase, `#` -> `--`, strip non-alphanumeric except `-`.

**Privacy note:** Handle mappings are publicly enumerable. Communities SHOULD treat this as opt-in.

### 2.5 Domain Migration

```
<uid>._m.<old-domain>  TXT  "v=1;to=<new-domain>;ts=<iso-timestamp>;sig=<base64url>"
```

The `sig` field is the user's Ed25519 signature over `uid|to|ts`, proving the migration is authorized by the key holder, not the domain operator. Clients that see this record (or have the key pinned) can follow the pointer automatically.

---

## 3. Dual-Source DNS Verification

When a client connects to a server, it can verify the server's identity against two independent DNS sources.

### 3.1 Verification Flow

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

### 3.2 Trust Modes

Clients SHOULD support configurable trust levels:

| Mode     | Requirement                     | Use Case                    |
|----------|---------------------------------|-----------------------------|
| Relaxed  | Either source sufficient        | Casual use, one zone down   |
| Standard | At least one source + TOFU pin  | Default for most users      |
| Strict   | Both sources must agree         | High-trust communities      |

### 3.3 TOFU (Trust On First Use)

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

## 4. Mutual Authentication

### 4.1 Handshake

After TLS is established, both sides prove identity using the same Ed25519 challenge-response:

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
        |  + sig = Sign(user_key, nonce_s|nonce_c|     |
        |          server_uid|timestamp)               |
        |<---------------------------------------------|
        |                                              |
        |  Server verifies user sig                    |
        |  via DNS lookup                              |
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

### 4.2 Anonymous / Lightweight Connection

Not every connection requires mutual auth. Servers MAY support:

- **Server-verified only:** Client verifies server identity but connects anonymously.
- **Token-based:** Client presents a JWT from the SSO instead of doing direct key auth. Useful when the client doesn't want to expose its UID to every server.

---

## 5. SSO Integration

The SSO/Identity Provider is a convenience layer. It issues short-lived tokens so users don't need to perform challenge-response with every individual server.

### 5.1 SSO Authentication Flow

```
User                        SSO                         Game Server
 |                           |                                |
 |  "I am <uid>"             |                                |
 |-------------------------->|                                |
 |                           |                                |
 |  challenge (nonce)        |                                |
 |<--------------------------|                                |
 |                           |                                |
 |  Sign(user_key, nonce)    |                                |
 |-------------------------->|                                |
 |                           |                                |
 |    SSO resolves UID keys from DNS                          |
 |    SSO verifies signature                                  |
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

### 5.2 SSO Properties

The SSO is **stateless with respect to identity**:
- Does NOT store passwords (keys are user-held)
- Does NOT own the user's identity
- Does NOT need to be always-online (direct mutual auth still works)
- CAN be replaced without losing any user identities
- CAN be run by any community member who publishes an `_idp` record

### 5.3 JWT Claims

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

## 6. Key Storage and Recovery

### 6.1 Three-Layer Recovery Model

| Layer | Storage                  | Protected By             | Survives              |
|-------|--------------------------|--------------------------|------------------------|
| 1     | Device keychain/keystore | OS biometric / device PIN | Device loss: NO       |
| 2     | SSO server (encrypted)   | User password (Argon2id)  | SSO death: NO         |
| 3     | Cold backup key (BIP38-style) | Passphrase (Argon2id) | Everything            |

Each layer is independently sufficient to recover the identity. Users choose their comfort level.

### 6.2 Layer 1 — Device Cache

Private key stored in OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service) or encrypted file. Protected by device biometrics or local PIN.

**Fast path:** User taps fingerprint -> key is unlocked -> challenge-response -> JWT -> logged in.

### 6.3 Layer 2 — SSO Encrypted Backup

The SSO stores an encrypted blob it cannot read:

```json
{
  "uid": "01j5a3k7pm9qwr4txyz6bn8vhe",
  "version": 1,
  "argon2_params": {
    "variant": "argon2id",
    "memory_kb": 262144,
    "iterations": 3,
    "parallelism": 4
  },
  "salt": "<base64url, 16 bytes>",
  "nonce": "<base64url, 12 bytes>",
  "ciphertext": "<base64url, AES-256-GCM encrypted private key + auth tag>"
}
```

**Encryption:** Argon2id(password, salt) -> 256-bit key -> AES-256-GCM(key, nonce, private_key)

The server enforces rate limiting on retrieval attempts (e.g. 5 attempts per hour, exponential backoff).

### 6.4 Layer 3 — Cold Backup Key (BIP38-Style)

At registration, the client generates a printable recovery string:

```
idk1-7Ghx9mRk4Qp2Vn8Lw3Jt6Yb5Xz0Fc1Ds4Ae7Hm9Nq2Ur5Wj8Ko3Pi6Sl
```

**Format:**
```
+----------+--------+-----------+---------+--------------------------+
| prefix   | version| argon2    | salt    | encrypted private key    |
| "idk1-"  | 1 byte | params    | 16 bytes| + AES-256-GCM tag        |
|          |        | 3 bytes   |         | 48 bytes                 |
+----------+--------+-----------+---------+--------------------------+

Encoded: Base58Check (with 4-byte checksum)
```

**Recovery flow:**
1. User enters backup string + passphrase
2. Client decodes Base58Check, validates checksum
3. Client derives key via Argon2id with embedded params
4. Client decrypts private key
5. User has full identity -- can register with any SSO or authenticate directly

**Passphrase guidance:**
- Minimum 12 characters recommended
- Argon2id with aggressive params (256MB memory) to resist offline brute-force
- Optional: offer BIP39-style mnemonic (24 words) as alternative encoding

---

## 7. Registration Flow

### 7.1 New User

```
1.  Client generates ULID -> uid
2.  Client generates Ed25519 keypair -> (private_key, public_key)
3.  Client derives encryption key from user's password via Argon2id
4.  Client encrypts private_key -> encrypted_blob
5.  Client generates cold backup string -> displays to user
6.  Client sends to SSO:
      { uid, public_key, encrypted_blob, salt, argon2_params }
7.  SSO publishes public key to DNS:
      <uid>._k.<domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<pk>"
8.  Client stores private key in device keychain
9.  Done -- user never saw any cryptography
```

### 7.2 New Server

```
1.  Operator generates ULID -> server_uid
2.  Operator generates Ed25519 keypair
3.  Operator publishes to own DNS zone:
      _k.<server-domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<pk>;uid=<server_uid>"
4.  Operator registers with identity domain (optional):
      <server_uid>._k.<identity-domain> TXT "v=1;k=ed25519;kid=<kid>;pk=<pk>;type=server"
5.  Operator stores private key securely + generates cold backup
```

---

## 8. HTTPS Fallback

Some networks block non-standard DNS lookups. The spec defines an HTTPS fallback serving identical data.

### Endpoints (relative to `issuer`)

| Path                          | Returns                              |
|-------------------------------|--------------------------------------|
| `/.well-known/jwks.json`     | Provider signing keys (JWKS)         |
| `/k/<uid>`                    | JSON array of entity public keys     |
| `/h/<normalized-handle>`     | JSON: `{ "uid": "..." }`            |

### Resolution Order

1. Try DNS (fast, cacheable, decentralized)
2. Fall back to HTTPS (reliable, CDN-friendly)
3. Check device cache / TOFU pins (works offline)

---

## 9. Key Rotation & TTL Guidance

### Rotation Lifecycle

```
Phase 1: STABLE       -> single key, flag=primary, TTL=3600
Phase 2: PRE-ROTATE   -> add new key flag=primary, old key flag=rotate, TTL=300
Phase 3: OVERLAP      -> both keys valid, sign with new key. Duration >=2x old TTL.
Phase 4: RETIRE       -> remove old key (or flag=revoked), TTL back to 3600
```

### TTL Strategy

| State            | Recommended TTL |
|------------------|-----------------|
| Stable           | 3600 (1 hour)   |
| During rotation  | 300 (5 min)     |
| Emergency revoke | 60 (1 min)      |

### Client Behavior

- Accept any non-revoked key in the current DNS/HTTPS response
- TOFU-warn on unexpected key changes
- Pin key fingerprints locally
- Never cache keys beyond DNS TTL

---

## 10. Security Considerations

**DNS is not private.** Public keys are public. Do not store sensitive data in DNS.

**DNSSEC recommended** but not required. Without DNSSEC, network attackers could spoof DNS. The HTTPS fallback (TLS) and dual-source verification provide alternative trust paths.

**Dual-source verification** (section 3) means compromising a server's identity requires compromising two independent DNS zones simultaneously.

**Revocation latency.** DNS caching delays revocation. Mitigation: short-lived JWTs (5-min expiry). "Revoke" = "stop issuing tokens" + wait for TTL.

**Brute-force on backups.** Cold backup keys are vulnerable to offline attack if passphrase is weak. Mitigation: Argon2id with 256MB memory, strong passphrase guidance.

**SSO compromise.** A compromised SSO can issue fraudulent JWTs but CANNOT steal private keys (encrypted blobs are opaque). Servers MAY require direct mutual auth for high-security actions.

**Enumeration.** UIDs are opaque. Handle mappings are enumerable -- keep them opt-in.

---

## 11. Implementation Notes (.NET)

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

## 12. What This Spec Does NOT Cover (By Design)

Explicitly out of scope to keep ops costs near zero:

- Profiles, avatars, display names -- optional HTTPS / plugins
- Discovery / friend search -- invite codes, QR, optional directory servers
- OAuth / OIDC sessions -- layer on top; this spec provides key material
- Private messaging key exchange -- future extension (X25519)
- Payments, reputation, moderation -- application-layer concerns
- Access control / permissions -- server-side policy, not identity-layer

---

## Appendix A: Quick Reference — DNS Records

```
# Identity provider discovery
_idp.id.example.org  TXT  "v=1;issuer=https://id.example.org"

# User public key
<uid>._k.id.example.org  TXT  "v=1;k=ed25519;kid=2026-02;pk=BASE64URL..."

# Server key (in identity domain)
<server-uid>._k.id.example.org  TXT  "v=1;k=ed25519;kid=2026-02;pk=BASE64URL...;type=server"

# Server key (self-published in own zone)
_k.chat.devreg.org  TXT  "v=1;k=ed25519;kid=2026-02;pk=BASE64URL...;uid=<server-uid>"

# Handle mapping (optional)
alice--1234._h.id.example.org  TXT  "v=1;uid=01j5a3k7pm9qwr4txyz6bn8vhe"

# Domain migration
<uid>._m.id.example.org  TXT  "v=1;to=id.newdomain.org;ts=2026-03-01T00:00:00Z;sig=BASE64URL..."
```

**Total DNS records per user: 1-2 TXT.  Per server: 2-3 TXT.  That's it.**

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
