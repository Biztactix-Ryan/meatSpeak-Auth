# DNS Record Reference — v0.4

**Status:** Draft
**Parent document:** [IDENTITY-SPEC.md](IDENTITY-SPEC.md)
**Companion documents:** [RECOVERY-SPEC.md](RECOVERY-SPEC.md)

This document is the **normative reference** for all DNS record types in the MeatSpeak identity system. It defines record formats, field semantics, encoding rules, TTL strategy, and HTTPS fallback endpoints. Keep this open while coding.

---

## 1. Conventions

### 1.1 Identity Domain

All identity records live under a configurable **identity domain**, e.g. `id.example.org`. Throughout this document, `<domain>` refers to this identity domain unless otherwise noted.

### 1.2 Field Encoding Rules

| Encoding | Used For | Rules |
|----------|----------|-------|
| Base64url | Public keys, signatures, ciphertext, sealed boxes | [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5). No padding (`=`). Alphabet: `A-Za-z0-9-_`. |
| ISO 8601 | Timestamps | UTC, full precision: `YYYY-MM-DDTHH:MM:SSZ`. Always include the `Z` suffix. |
| Crockford Base32 | UIDs (ULID) | 26 characters, lowercase in DNS labels. Alphabet: `0-9a-hjkmnp-tv-z`. |
| Duration | Window fields | Integer followed by unit: `d` (days), `h` (hours). Example: `14d`, `60d`. |

All field values are UTF-8 strings. Semicolons (`;`) and equals signs (`=`) MUST NOT appear in field values.

### 1.3 TXT Record Size Limits

DNS TXT records are composed of one or more character strings, each with a maximum length of **255 bytes** ([RFC 1035 §3.3.14](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14)). For identity records that exceed 255 bytes:

- The record MUST be split into multiple character strings within a single TXT RDATA.
- Resolvers concatenate the strings in order to reconstruct the full value.
- Implementations MUST handle concatenation transparently.

In practice, most identity records fit within a single 255-byte string. Key records with enrollment signatures and encrypted device names may require two strings.

**Example (multi-string TXT record):**
```
<uid>._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=a7f3b2c1;pk=dGhpcyBpcyBhIGZha2Uga2V5IGJ1dCBpdCBk"
  "ZW1vbnN0cmF0ZXMgbXVsdGktc3RyaW5n;device=<sealed-box>;enroll_sig=BASE64URL..."
```

### 1.4 Multi-Value Records

Some DNS labels carry multiple TXT records (e.g., a root key and several device keys on the same `_k` label). These are published as **separate TXT resource records** on the same label, not as multiple strings within one record.

Resolvers querying a label receive all TXT records. Implementations MUST:

1. Parse each TXT record independently.
2. Use the `flag`, `kid`, and `device` fields to distinguish records.
3. Not assume any ordering of returned records.

### 1.5 Sealed Box Encryption (Ed25519 to X25519)

Several record types use **sealed box encryption** to protect metadata from DNS observers while allowing specific key holders to decrypt. This uses the Ed25519-to-X25519 key conversion available in libsodium.

**How it works:**
1. Convert the recipient's Ed25519 public key to X25519: `recipient_x25519_pk = crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)`
2. Encrypt: `sealed = crypto_box_seal(plaintext, recipient_x25519_pk)`
3. Encode the sealed box as Base64url for storage in DNS.

**Decryption** (requires the recipient's private key):
1. Convert Ed25519 keypair to X25519: `x25519_sk = crypto_sign_ed25519_sk_to_curve25519(ed25519_sk)`
2. Decrypt: `plaintext = crypto_box_seal_open(sealed, x25519_pk, x25519_sk)`

**Overhead:** Sealed box adds 48 bytes (32-byte ephemeral public key + 16-byte MAC). A 20-byte plaintext becomes 68 bytes raw / ~91 chars Base64url.

**Two encryption patterns are used throughout this spec:**

| Pattern | Encrypt To | Purpose | Decrypted By |
|---------|-----------|---------|-------------|
| **Owner-readable** | User's root public key | Encrypted device names, RC friendly names | User (with root key) |
| **Recipient-readable** | Recipient's public key | RC authorization (RCID) | Designated recovery contact |

---

## 2. Identity Provider Discovery (`_idp`)

### 2.1 Record Format

```
_idp.<domain>  TXT  "v=1;issuer=https://<domain>;jwks=/.well-known/jwks.json"
```

### 2.2 Field Table

| Field    | Required | Type   | Description |
|----------|----------|--------|-------------|
| `v`      | Yes      | Integer | Spec version. Currently `1`. |
| `issuer` | Yes      | URL    | Canonical HTTPS origin of the identity provider. No trailing slash. |
| `jwks`   | No       | Path   | Path to JWKS endpoint, relative to `issuer`. Default: `/.well-known/jwks.json`. |

### 2.3 Examples

**Minimal:**
```
_idp.id.example.org.  3600  IN  TXT  "v=1;issuer=https://id.example.org"
```

**With explicit JWKS path:**
```
_idp.id.example.org.  3600  IN  TXT  "v=1;issuer=https://id.example.org;jwks=/auth/jwks.json"
```

### 2.4 Implementation Notes

- There MUST be exactly one `_idp` TXT record per identity domain.
- The `issuer` value is used as the `iss` claim in JWTs. It MUST match exactly (case-sensitive, no trailing slash).
- Clients resolve this record to discover where to fetch JWKS for JWT verification.

---

## 3. Entity Keys (`_k`)

### 3.1 Record Format

```
<uid>._k.<domain>  TXT  "v=1;k=<alg>;kid=<key-id>;pk=<base64url-pubkey>"
```

### 3.2 Field Table

| Field        | Required | Type        | Description |
|--------------|----------|-------------|-------------|
| `v`          | Yes      | Integer     | Spec version. Currently `1`. |
| `k`          | Yes      | String      | Key algorithm. MUST be `ed25519`. |
| `kid`        | Yes      | String      | Key identifier. For device keys: MUST be opaque (e.g., first 8 hex chars of `BLAKE2b(pk)`). For root keys: MAY use `root-YYYY` format. See §3.5. |
| `pk`         | Yes      | Base64url   | Ed25519 public key (32 bytes encoded). |
| `exp`        | No       | ISO 8601    | Expiry hint. Advisory only — implementations SHOULD warn but MAY still accept. |
| `flag`       | No       | String      | Comma-separated flags. See §3.5. |
| `type`       | No       | String      | Entity type: `user`, `server`, `idp`. Default: `user`. |
| `device`     | No       | Base64url   | **Sealed box** containing the human-readable device name, encrypted to the user's root X25519 public key. Only for device keys. See §3.4. |
| `enroll_sig` | No       | Base64url   | Root key signature authorizing this device key. Only for device keys. See §3.7. |

### 3.3 Root Key Records

Root keys are published with `flag=root`. They represent the identity anchor.

**Rules:**
- One root key per UID at any time (during rotation, the old key is revoked before the new one is published).
- MUST NOT be used for authentication — only for signing management operations.
- Management operations signed by root key: device enrollment, device revocation, recovery contact designation, recovery contact change, migration statements.
- The root key also serves as the encryption key for owner-readable sealed boxes (via Ed25519-to-X25519 conversion).

**Example:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=root-2026;pk=cm9vdCBrZXkgZ29lcyBoZXJl;flag=root"
```

### 3.4 Device Key Records

Device keys are per-device Ed25519 keypairs used for all authentication. They include the `device` field (an encrypted device name) and an `enroll_sig` proving the root key authorized them.

**Encrypted device name:** The `device` field contains a sealed box encrypted to the user's root public key (X25519-converted). Only the root key holder can decrypt to see the human-readable name (e.g., "ryan-desktop").

```
device = Base64url(SealedBox(root_x25519_pk, "ryan-desktop"))
```

**Why encrypt?** Plaintext device names like `device=ryan-desktop` leak information about the user's hardware and habits. Encrypted names are opaque to all observers; only the user (with their root key) can see which device is which.

**Opaque key IDs:** The `kid` field for device keys MUST be opaque to prevent leaking device information through the key identifier. Recommended: first 8 hex characters of `BLAKE2b(pk)`.

**Example:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=a7f3b2c1;pk=ZGV2aWNlIGtleSBnb2VzIGhlcmU;device=k8Tn2pFxQm4rV7jLwBs9YhD3gCeAv6RKXJ0NfMqUcWdHb5lzSoI1EiPtGyu;enroll_sig=ZW5yb2xsbWVudCBzaWduYXR1cmU"
```

An observer sees `device=k8Tn2pFx...` (opaque) and `kid=a7f3b2c1` (opaque). They know it's a device key, but not which device.

### 3.5 Flag Values and Semantics

| Flag       | Applies To  | Meaning |
|------------|-------------|---------|
| `root`     | Root key    | This is the identity anchor key. MUST NOT be used for authentication. One per UID. |
| `primary`  | Device key  | This is the user's preferred device key for the stable state. Informational. |
| `rotate`   | Device key  | This key is being phased out during rotation. Still valid until removed or revoked. |
| `revoked`  | Any key     | This key has been permanently revoked. Relying parties MUST reject immediately. |
| `contested`| Device key  | Set during `full_recovery` state. Relying parties SHOULD treat with reduced trust. |

Flags are comma-separated when multiple apply: `flag=primary,rotate`.

**Key ID conventions:**

| Key Type | `kid` Format | Example |
|----------|-------------|---------|
| Root key | `root-YYYY` or `root-YYYY-MM` | `root-2026` |
| Device key | First 8 hex chars of `BLAKE2b(pk)` | `a7f3b2c1` |
| Server key | `YYYY-MM` or short slug | `2026-02`, `srv-2026` |

Device key IDs MUST be opaque to prevent leaking device information. Implementations MUST NOT use descriptive names like `desktop-2026` or `phone-2026` as key IDs.

### 3.6 Multiple Keys on One Label

Resolving `<uid>._k.<domain>` returns **all** TXT records for that label — the root key and all device keys. Implementations MUST:

1. Parse each TXT record independently.
2. Identify the root key by `flag=root`.
3. Identify device keys by the presence of `device=<sealed-box>`.
4. Skip any record with `flag=revoked` for authentication purposes (but retain for audit/display).
5. Not assume any particular ordering.

**Example response (3 records on one label):**
```
01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=root-2026;pk=cm9vdCBrZXk;flag=root"

01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=a7f3b2c1;pk=ZGVza3RvcCBrZXk;device=k8Tn2pFxQm4rV7jL;enroll_sig=c2lnMQ"

01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=e9d4f8a0;pk=cGhvbmUga2V5;device=Qx7mWnK4pLs8Bf2T;enroll_sig=c2lnMg"
```

An observer sees: one root key and two device keys. They cannot determine what devices they represent.

### 3.7 Enrollment Signature Verification

The `enroll_sig` field proves the root key authorized a device key. Verification steps:

1. Extract the root key from the same `_k` label (the record with `flag=root`).
2. Construct the enrollment message:
   ```
   message = "enroll" | uid | device_kid | device_pk | timestamp
   ```
   Where `|` is byte concatenation using the raw UTF-8 bytes of each field.
3. Decode `enroll_sig` from Base64url.
4. Verify: `Ed25519.Verify(root_public_key, message, enroll_sig)`.

**Pseudocode (.NET):**
```csharp
bool VerifyEnrollment(byte[] rootPk, string uid, string deviceKid,
                      byte[] devicePk, string timestamp, byte[] enrollSig)
{
    // Construct canonical message
    var message = Encoding.UTF8.GetBytes("enroll")
        .Concat(Encoding.UTF8.GetBytes(uid))
        .Concat(Encoding.UTF8.GetBytes(deviceKid))
        .Concat(devicePk)
        .Concat(Encoding.UTF8.GetBytes(timestamp))
        .ToArray();

    return Ed25519.Verify(rootPk, message, enrollSig);
}
```

**Important:** The `timestamp` used in verification is the timestamp from when enrollment was originally performed. This timestamp is not stored in DNS — the enrolling client and identity server must agree on it at enrollment time. Implementations MAY include a `ts` field in device key records for this purpose.

### 3.8 Examples

**Root key + two devices (encrypted names):**
```
01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=root-2026;pk=cm9vdCBrZXk;flag=root"

01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=a7f3b2c1;pk=ZGVza3RvcCBrZXk;flag=primary;device=k8Tn2pFxQm4rV7jLwBs9YhD3gCeAv6RKXJ0NfMqUcWdHb5lzSoI1EiPtGyu;enroll_sig=ZW5yb2xsLWRlc2t0b3A"

01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=e9d4f8a0;pk=cGhvbmUga2V5;device=Qx7mWnK4pLs8Bf2TgVjRcY0hAv3DwZeU9rN6XoJtHi1aPkEy5CdMlGqSuO;enroll_sig=ZW5yb2xsLXBob25l"
```

User decrypts `device` fields with root key -> sees "ryan-desktop" and "ryan-phone". Observer sees opaque blobs.

**During device key rotation:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  300  IN  TXT
  "v=1;k=ed25519;kid=root-2026;pk=cm9vdCBrZXk;flag=root"

01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  300  IN  TXT
  "v=1;k=ed25519;kid=a7f3b2c1;pk=b2xkIGRlc2t0b3Aga2V5;flag=rotate;device=k8Tn2pFxQm4rV7jL;enroll_sig=c2lnMQ"

01j5a3k7pm9qwr4txyz6bn8vhe._k.id.example.org.  300  IN  TXT
  "v=1;k=ed25519;kid=b2e5c9d3;pk=bmV3IGRlc2t0b3Aga2V5;flag=primary;device=Rm8nPqLx2Ws5Tv7j;enroll_sig=c2lnMg"
```

---

## 4. Server Self-Published Keys (`_k` on server domain)

### 4.1 Record Format

```
_k.<server-domain>  TXT  "v=1;k=ed25519;kid=<key-id>;pk=<base64url>;uid=<server-uid>"
```

### 4.2 Field Table

| Field  | Required | Type      | Description |
|--------|----------|-----------|-------------|
| `v`    | Yes      | Integer   | Spec version. Currently `1`. |
| `k`    | Yes      | String    | Key algorithm. MUST be `ed25519`. |
| `kid`  | Yes      | String    | Key identifier. |
| `pk`   | Yes      | Base64url | Ed25519 public key (32 bytes encoded). |
| `uid`  | Yes      | ULID      | Server's UID, linking this record to the identity domain entry. |

Note: The `uid` field is required here (unlike entity key records in the identity domain) because the server domain label doesn't contain the UID. Server keys do not use encrypted device names (servers are public infrastructure).

### 4.3 Dual-Source Pattern

Servers publish the same key in two independent DNS zones. Clients compare both to establish trust.

**Side-by-side zone comparison:**

```
# Zone: id.example.org (operated by identity community)
# Contains: server UID as label, type=server, no uid field needed
01j5srv7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=2026-02;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;type=server"

# Zone: chat.devreg.org (operated by server owner)
# Contains: no UID label, uid field required for linking
_k.chat.devreg.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=2026-02;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;uid=01j5srv7pm9qwr4txyz6bn8vhe"
```

The `pk` values MUST be identical. If they differ, clients MUST warn the user of possible compromise or misconfiguration.

### 4.4 Examples

**Server with both zones configured:**
```
# Identity domain
01j5srv7pm9qwr4txyz6bn8vhe._k.id.example.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=srv-2026;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;type=server"

# Server's own domain
_k.chat.devreg.org.  3600  IN  TXT
  "v=1;k=ed25519;kid=srv-2026;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;uid=01j5srv7pm9qwr4txyz6bn8vhe"
```

**Server with only own domain (no identity domain registration):**
```
_k.irc.smallcommunity.net.  3600  IN  TXT
  "v=1;k=ed25519;kid=2026-01;pk=c21hbGwgc2VydmVyIGtleQ;uid=01j5xyz9ab3cde4fgh5ijk6lmn"
```

---

## 5. Handle Mapping (`_h`)

### 5.1 Record Format

```
<normalized-handle>._h.<domain>  TXT  "v=1;uid=<uid>"
```

### 5.2 Field Table

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `v`   | Yes      | Integer | Spec version. Currently `1`. |
| `uid` | Yes      | ULID | The UID that owns this handle. |

### 5.3 Handle Normalization Rules

Handles are human-readable identifiers mapped to UIDs. Before use as a DNS label, handles MUST be normalized:

| Rule | Input | Output |
|------|-------|--------|
| Lowercase | `Alice` | `alice` |
| `#` becomes `--` | `alice#1234` | `alice--1234` |
| Strip non-alphanumeric except `-` | `al!ce.x` | `alcex` |
| Consecutive `-` collapsed | `a---b` | `a-b` |
| Leading/trailing `-` stripped | `-alice-` | `alice` |

**Edge cases:**
- Empty handle after normalization: invalid, MUST be rejected.
- Handle that normalizes to a pure number: valid (UIDs use a different subdomain).
- Maximum length: 63 characters (DNS label limit).
- Handles containing only stripped characters: invalid after normalization.

### 5.4 Examples

```
alice--1234._h.id.example.org.  3600  IN  TXT  "v=1;uid=01j5a3k7pm9qwr4txyz6bn8vhe"
```

```
ryan._h.id.example.org.  3600  IN  TXT  "v=1;uid=01j5b4l8qn0rxs5uya7co9wif"
```

### 5.5 Privacy Considerations

Handle mappings are **publicly enumerable**. Anyone who can query DNS can discover the handle-to-UID mapping. Communities SHOULD:

- Treat handle publication as opt-in.
- Document that handles are public.
- Allow users to remove their handle mapping at any time.
- Consider that handle enumeration reveals community membership.

---

## 6. Domain Migration (`_m`)

### 6.1 Record Format

```
<uid>._m.<old-domain>  TXT  "v=1;to=<new-domain>;ts=<iso-timestamp>;sig=<base64url>"
```

### 6.2 Field Table

| Field | Required | Type      | Description |
|-------|----------|-----------|-------------|
| `v`   | Yes      | Integer   | Spec version. Currently `1`. |
| `to`  | Yes      | Domain    | New identity domain the user is migrating to. |
| `ts`  | Yes      | ISO 8601  | Timestamp of migration statement. |
| `sig` | Yes      | Base64url | Ed25519 signature proving migration is authorized by the key holder. |

### 6.3 Signature Construction

The `sig` field is constructed by signing the canonical migration message with the user's root key:

```
message = uid | to | ts
```

Where `|` is byte concatenation of the raw UTF-8 string values. The signature proves the key holder (not the domain operator) authorized the migration.

**Step-by-step:**
1. Encode each field as UTF-8 bytes: `uid_bytes`, `to_bytes`, `ts_bytes`.
2. Concatenate: `message = uid_bytes + to_bytes + ts_bytes`.
3. Sign: `sig = Ed25519.Sign(root_private_key, message)`.
4. Encode signature as Base64url (no padding).

### 6.4 Client Migration-Following Behavior

When a client resolves a UID and encounters an `_m` record on the old domain:

1. Verify `sig` against the user's root key published on the old domain.
2. If valid, resolve the UID on the new domain (`to` field).
3. Verify the root key on the new domain matches the key that signed the migration.
4. Update local UID-to-domain mapping.
5. On subsequent lookups, resolve from the new domain directly.

Clients SHOULD alert the user on first migration follow ("User X has moved to new-domain.org").

Clients MUST NOT follow migration chains longer than 3 hops (prevents infinite loops from circular migrations).

### 6.5 Examples

```
01j5a3k7pm9qwr4txyz6bn8vhe._m.id.example.org.  3600  IN  TXT
  "v=1;to=id.newdomain.org;ts=2026-03-01T00:00:00Z;sig=bWlncmF0aW9uIHNpZ25hdHVyZQ"
```

---

## 7. Recovery Contact (`_rc`)

Recovery contact records use **blind RCIDs** — the recovery contact's identity is hidden behind sealed box encryption. No UID, public key, or identifying information about the recovery contact is visible in DNS. See [RECOVERY-SPEC.md §3](RECOVERY-SPEC.md) for the full recovery contact lifecycle.

### 7.1 Record Format

```
<uid>._rc.<domain>  TXT  "v=1;rcid=<base64url>;name=<base64url>;window=14d;death_window=60d"
```

### 7.2 Field Table

| Field          | Required | Type      | Description |
|----------------|----------|-----------|-------------|
| `v`            | Yes      | Integer   | Spec version. Currently `1`. |
| `rcid`         | Yes      | Base64url | **Sealed box** containing the root key authorization signature, encrypted to the RC's X25519 public key. The RC decrypts this to prove their status. See §7.3. |
| `name`         | No       | Base64url | **Sealed box** containing a human-readable name for this RC (e.g., "Tara"), encrypted to the user's root X25519 public key. Only the user can decrypt. |
| `window`       | No       | Duration  | Waiting period for recovery operations. Default: `14d`. |
| `death_window` | No       | Duration  | Waiting period for death declaration. Default: `60d`. |

### 7.3 RCID Construction

The `rcid` field is a sealed box containing the root key's authorization signature, encrypted to the recovery contact's public key:

```
authorization = Sign(root_key, "recover" || uid || rc_pk || window || death_window || timestamp)
rcid = SealedBox(rc_x25519_pk, authorization)
```

**Step-by-step (at designation time):**
1. The user knows the RC's Ed25519 public key.
2. Sign the authorization: `auth_sig = Sign(root_key, "recover" || uid || rc_pk || window || death_window || timestamp)`.
3. Convert the RC's Ed25519 public key to X25519.
4. Seal: `rcid = crypto_box_seal(auth_sig, rc_x25519_pk)`.
5. Encode as Base64url.

**What's inside the RCID:** The root key's Ed25519 signature over a message that binds the RC's public key to this user's recovery authorization. Only the RC can extract this signature.

### 7.4 RC Verification Flow

When a recovery contact initiates recovery, they prove their authorization:

```
RC                                         Identity Server
  |                                              |
  | Fetch _rc records for the user               |
  | Try decrypting each rcid with my private key |
  | One succeeds -> I have the root_sig          |
  |                                              |
  | Present: my_pk + root_sig + signed request   |
  |--------------------------------------------->|
  |                                              |
  |   Server reconstructs the signed message:    |
  |   "recover" || uid || presented_pk ||        |
  |   window || death_window || timestamp        |
  |                                              |
  |   Verify(root_pk, root_sig, message) ✓       |
  |   -> Root key authorized this pk as RC       |
  |                                              |
  |   Verify(presented_pk, request_sig) ✓        |
  |   -> RC holds the corresponding private key  |
  |                                              |
  | Authorized                                   |
  |<---------------------------------------------|
```

**Key properties:**
- The server learns the RC's public key only when recovery is triggered, never at rest.
- The RC discovers which `_rc` record is theirs by attempting decryption — they cannot determine who else is designated as RC.
- An observer cannot determine the RC's identity from the DNS record.

### 7.5 Encrypted RC Name

The `name` field is a sealed box encrypted to the user's root public key:

```
name = SealedBox(user_root_x25519_pk, "Tara")
```

This lets the user decrypt and see a friendly name for each RC. Essential when multiple RCs are designated (future M-of-N), as the RCIDs themselves are indistinguishable.

### 7.6 Examples

**Single recovery contact:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._rc.id.example.org.  3600  IN  TXT
  "v=1;rcid=Hx8k2Qm9Tp4vN7jLwBs3YhD6gCeAv1RK_XJ0NfMqUcWd5lzSoI1EiPt_Gyu3bF8nKw2xR7pT;name=a8Fk2mNx9pQ3rLvJw;window=14d;death_window=60d"
```

**Multiple recovery contacts (future M-of-N):**
```
01j5a3k7pm9qwr4txyz6bn8vhe._rc.id.example.org.  3600  IN  TXT
  "v=1;rcid=Hx8k2Qm9Tp4vN7jLwBs3YhD6gCeAv1RK;name=a8Fk2mNx9pQ3rLvJw;window=14d;death_window=60d"

01j5a3k7pm9qwr4txyz6bn8vhe._rc.id.example.org.  3600  IN  TXT
  "v=1;rcid=Px3mWnK4pLs8Bf2TgVjRcY0hAv3DwZeU;name=b7Gj9kRw2xFn7sT8;window=14d;death_window=60d"

01j5a3k7pm9qwr4txyz6bn8vhe._rc.id.example.org.  3600  IN  TXT
  "v=1;rcid=Qx9nZoL5qMt9Cg3UhWkScZ1iBw4ExAf;name=c6Hk0lSx3yGo8uU9;window=7d;death_window=30d"
```

An observer sees: 3 opaque blobs. Cannot determine who any of them are. Even the RCs themselves can only identify their own record (by attempting decryption), not each other's.

---

## 8. Recovery Contact Change (`_rcc`)

### 8.1 Record Format

```
<uid>._rcc.<domain>  TXT  "v=1;old_rcid=<base64url>;new_rcid=<base64url>;new_name=<base64url>;ts=<timestamp>;effective=<timestamp+7d>;sig=<base64url>"
```

### 8.2 Field Table

| Field       | Required | Type      | Description |
|-------------|----------|-----------|-------------|
| `v`         | Yes      | Integer   | Spec version. Currently `1`. |
| `old_rcid`  | Yes      | Base64url | The `rcid` value from the `_rc` record being replaced. Used to identify which RC is changing. |
| `new_rcid`  | Yes      | Base64url | New sealed box RCID for the replacement recovery contact (same construction as §7.3). |
| `new_name`  | No       | Base64url | Sealed box with friendly name for the new RC, encrypted to user's root key. |
| `ts`        | Yes      | ISO 8601  | Timestamp when the change was initiated. |
| `effective` | Yes      | ISO 8601  | Timestamp when the change takes effect (MUST be >= `ts` + 7 days). |
| `sig`       | Yes      | Base64url | Root key signature authorizing this change. |

### 8.3 Signature Construction

```
message = "rc_change" | uid | old_rcid | new_rcid | timestamp
```

Signed with the root key using byte-concatenation. The `old_rcid` and `new_rcid` are included as their raw Base64url string bytes.

### 8.4 Lifecycle: Pending, Effective, Removed

**Pending (days 0-7):**
- `_rcc` record is published.
- The user notifies both old and new recovery contacts out-of-band (the server does not know their identities).
- The old RC can detect the pending change by checking for `_rcc` records and recognizing their `old_rcid`.
- Any device key OR root key can cancel the change (identity server removes the `_rcc` record).
- Old recovery contact retains full recovery powers.

**Effective (after 7 days):**
- `_rcc` record is removed.
- The `_rc` record matching `old_rcid` is replaced with a new `_rc` record containing `new_rcid` and `new_name`.
- New recovery contact has full recovery powers.

**Blocked:**
- If the account is in any active recovery state (`root_rotation`, `full_recovery`, `death`), recovery contact changes are BLOCKED. The identity server MUST reject `_rcc` publication.

### 8.5 Examples

**Pending change:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._rcc.id.example.org.  300  IN  TXT
  "v=1;old_rcid=Hx8k2Qm9Tp4vN7jLwBs3YhD6gCeAv1RK;new_rcid=Zw4pXnM8tRu2Yc6VqKjFbE7iDsGhL0;new_name=d5Il1mTy4zHp9vV0;ts=2026-03-01T00:00:00Z;effective=2026-03-08T00:00:00Z;sig=cmNfY2hhbmdlIHNpZw"
```

Note the shorter TTL (300s) during the pending period to ensure timely propagation of any cancellation.

---

## 9. Account State (`_s`)

### 9.1 Record Format

```
<uid>._s.<domain>  TXT  "v=1;state=<state>;ts=<timestamp>;expires=<timestamp>;sig=<base64url>"
```

### 9.2 Field Table

| Field     | Required | Type      | Description |
|-----------|----------|-----------|-------------|
| `v`       | Yes      | Integer   | Spec version. Currently `1`. |
| `state`   | Yes      | String    | Account state. One of: `root_rotation`, `full_recovery`, `death`, `tombstone`. |
| `ts`      | Yes      | ISO 8601  | Timestamp when this state was entered. |
| `expires` | Conditional | ISO 8601 | When the grace period ends. Not present for `tombstone`. |
| `sig`     | Conditional | Base64url | Signature authorizing the state change. Not present for `tombstone`. |

Note: The `by` field from earlier versions has been removed. The initiator's identity is protected by the blind RCID scheme — it is verified cryptographically at initiation time but not published in DNS.

### 9.3 State Values and Meanings

| State | What Relying Parties Do |
|-------|------------------------|
| *(no record)* | **Stable.** Normal operation. Accept any non-revoked device key. |
| `root_rotation` | **Caution.** Root key is being replaced. Continue accepting existing device keys normally. Alert the user that the identity is undergoing root key rotation. |
| `full_recovery` | **Reduced trust.** All existing device keys are contested. Limit sensitive actions (e.g., require additional verification for admin operations). Display warnings to other users. |
| `death` | **Winding down.** Account is in death grace period. Existing sessions may continue but no new device enrollments. Display notice to other users. |
| `tombstone` | **Dead.** Reject all keys. UID is permanently burned. Display tombstone notice. Never re-enable. |

### 9.4 Tombstone Records

Tombstone is the permanent, terminal state. The record is simplified:

```
<uid>._s.<domain>  TXT  "v=1;state=tombstone;ts=<timestamp>"
```

No `expires` or `sig` fields. The tombstone record SHOULD be retained indefinitely to prevent UID reuse.

### 9.5 Examples

**Root rotation in progress:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._s.id.example.org.  300  IN  TXT
  "v=1;state=root_rotation;ts=2026-03-01T00:00:00Z;expires=2026-03-15T00:00:00Z;sig=cm90YXRpb24gc2ln"
```

**Full recovery in progress:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._s.id.example.org.  300  IN  TXT
  "v=1;state=full_recovery;ts=2026-03-01T00:00:00Z;expires=2026-03-15T00:00:00Z;sig=cmVjb3Zlcnkgc2ln"
```

**Death declaration:**
```
01j5a3k7pm9qwr4txyz6bn8vhe._s.id.example.org.  300  IN  TXT
  "v=1;state=death;ts=2026-03-01T00:00:00Z;expires=2026-04-30T00:00:00Z;sig=ZGVhdGggc2ln"
```

**Tombstone (permanent):**
```
01j5a3k7pm9qwr4txyz6bn8vhe._s.id.example.org.  86400  IN  TXT
  "v=1;state=tombstone;ts=2026-04-30T00:00:00Z"
```

See [RECOVERY-SPEC.md](RECOVERY-SPEC.md) for detailed state transition rules, grace periods, and cancellation policies.

---

## 10. TTL Strategy

### 10.1 Recommended TTLs by State

| State / Scenario     | Record Types Affected | Recommended TTL | Rationale |
|----------------------|-----------------------|-----------------|-----------|
| Stable               | `_k`, `_rc`, `_h`, `_idp` | 3600 (1 hour) | Low change frequency, cache-friendly. |
| During key rotation  | `_k`                  | 300 (5 min)     | Ensure new keys propagate quickly. |
| Emergency revocation | `_k`                  | 60 (1 min)      | Minimize window of compromised key acceptance. |
| Recovery state       | `_s`, `_k`            | 300 (5 min)     | State changes need fast propagation. |
| RC change pending    | `_rcc`, `_rc`         | 300 (5 min)     | Cancellations must propagate quickly. |
| Tombstone            | `_s`                  | 86400 (1 day)   | Permanent state, aggressive caching OK. |

### 10.2 TTL During Key Rotation

The 4-phase device key rotation lifecycle requires TTL coordination:

```
Phase 1: STABLE       -> single device key, flag=primary, TTL=3600
Phase 2: PRE-ROTATE   -> add new device key flag=primary, old key flag=rotate, TTL=300
Phase 3: OVERLAP      -> both device keys valid, sign with new key. Duration >=2x old TTL.
Phase 4: RETIRE       -> remove old device key (or flag=revoked), TTL back to 3600
```

The overlap period (Phase 3) MUST be at least 2x the previous TTL to ensure all caches have expired before the old key is removed. With the default stable TTL of 3600, the overlap MUST be at least 7200 seconds (2 hours).

### 10.3 TTL During Emergency Revocation

When a device key is compromised, the TTL should be dropped to 60 seconds. However, clients that have already cached the old TTL will continue accepting the compromised key until their cache expires.

**Mitigation sequence:**
1. Set `flag=revoked` on the compromised key with TTL=60.
2. Wait for the previous TTL to expire (up to 1 hour in the worst case).
3. Short-lived JWTs (5-minute expiry) provide a secondary mitigation: even if a cached key is used, tokens expire quickly.

### 10.4 Client Caching Behavior

- Accept any non-revoked device key in the current DNS/HTTPS response.
- Verify device key enrollment signatures against the root key.
- TOFU-warn on unexpected key changes.
- Pin key fingerprints locally.
- MUST NOT cache keys beyond the DNS TTL.
- SHOULD cache keys for the full TTL duration to reduce DNS load.
- MUST re-resolve if a signature verification fails (key may have rotated since last cache fill).

---

## 11. HTTPS Fallback Endpoints

Some networks block non-standard DNS lookups or DNS-over-HTTPS. The spec defines HTTPS endpoints serving identical data as a fallback.

### 11.1 Endpoint Table

All paths are relative to the `issuer` URL from the `_idp` record.

| Path                       | DNS Equivalent | Returns |
|----------------------------|---------------|---------|
| `/.well-known/jwks.json`  | `_idp` JWKS   | Provider signing keys (JWKS format) |
| `/k/<uid>`                 | `<uid>._k`    | JSON array of entity public keys |
| `/h/<normalized-handle>`  | `<handle>._h` | JSON: UID for handle |
| `/m/<uid>`                 | `<uid>._m`    | JSON: migration record |
| `/rc/<uid>`                | `<uid>._rc`   | JSON: recovery contact records (opaque RCIDs) |
| `/s/<uid>`                 | `<uid>._s`    | JSON: account state record |

### 11.2 JSON Response Formats

**`/k/<uid>` — Entity keys:**
```json
{
  "v": 1,
  "uid": "01j5a3k7pm9qwr4txyz6bn8vhe",
  "keys": [
    {
      "k": "ed25519",
      "kid": "root-2026",
      "pk": "cm9vdCBrZXk",
      "flag": "root"
    },
    {
      "k": "ed25519",
      "kid": "a7f3b2c1",
      "pk": "ZGVza3RvcCBrZXk",
      "flag": "primary",
      "device": "k8Tn2pFxQm4rV7jLwBs9YhD3gCeAv6RKXJ0NfMqUcWdHb5lzSoI1EiPtGyu",
      "enroll_sig": "ZW5yb2xsLWRlc2t0b3A"
    }
  ]
}
```

**`/h/<normalized-handle>` — Handle mapping:**
```json
{
  "v": 1,
  "uid": "01j5a3k7pm9qwr4txyz6bn8vhe"
}
```

**`/m/<uid>` — Migration record:**
```json
{
  "v": 1,
  "to": "id.newdomain.org",
  "ts": "2026-03-01T00:00:00Z",
  "sig": "bWlncmF0aW9uIHNpZ25hdHVyZQ"
}
```

**`/rc/<uid>` — Recovery contact records:**
```json
{
  "v": 1,
  "contacts": [
    {
      "rcid": "Hx8k2Qm9Tp4vN7jLwBs3YhD6gCeAv1RK_XJ0NfMqUcWd5lzSoI1EiPt_Gyu3bF8nKw2xR7pT",
      "name": "a8Fk2mNx9pQ3rLvJw",
      "window": "14d",
      "death_window": "60d"
    }
  ]
}
```

**`/s/<uid>` — Account state:**
```json
{
  "v": 1,
  "state": "root_rotation",
  "ts": "2026-03-01T00:00:00Z",
  "expires": "2026-03-15T00:00:00Z",
  "sig": "cm90YXRpb24gc2ln"
}
```

**`/s/<uid>` — Tombstone:**
```json
{
  "v": 1,
  "state": "tombstone",
  "ts": "2026-04-30T00:00:00Z"
}
```

**Error responses** (when no record exists):
```json
{
  "error": "not_found",
  "message": "No record found for the given identifier."
}
```

HTTP status codes: `200` for found, `404` for not found, `429` for rate-limited.

### 11.3 Resolution Order

Clients SHOULD resolve identity records in this order:

1. **DNS** (fast, cacheable, decentralized)
2. **HTTPS fallback** (reliable, CDN-friendly, works on restricted networks)
3. **Device cache / TOFU pins** (works offline)

See [IDENTITY-SPEC.md §8](IDENTITY-SPEC.md) for the full resolution strategy.

---

## 12. Security Considerations

These security considerations are specific to DNS record handling. See [IDENTITY-SPEC.md](IDENTITY-SPEC.md) for operational security and [RECOVERY-SPEC.md](RECOVERY-SPEC.md) for recovery-related threats.

**DNS is not private — but metadata can be.** Public keys are public by design. However, the sealed box encryption pattern (§1.5) protects sensitive metadata: device names are opaque, recovery contact relationships are hidden, and RC friendly names are encrypted. The only public information is the UID, public keys, and record structure.

**DNSSEC recommended but not required.** Without DNSSEC, network attackers could spoof DNS responses and serve fraudulent keys. Mitigations: HTTPS fallback (TLS provides authenticity), dual-source verification (two zones must agree), TOFU pinning (detects key changes after first use).

**DNS caching delays revocation.** A revoked key remains accepted by clients until their cached TTL expires. Mitigations: short-lived JWTs (5-minute expiry), aggressive TTL reduction during revocation (60s), client re-resolution on verification failure.

**Record tampering.** Without DNSSEC, an attacker who can modify DNS responses can:
- Inject rogue device keys (but cannot forge `enroll_sig` without the root key)
- Remove the `_s` record to hide an active recovery state
- Modify TTLs to extend cache lifetime of compromised keys

Enrollment signature verification and dual-source checking limit the impact of DNS-only attacks.

**Sealed box privacy model.** The blind RCID scheme provides strong privacy for recovery contact relationships:
- At rest: the RC's identity is hidden behind asymmetric encryption (sealed box). No UID, no public key, no identifiable information.
- At recovery time: the RC reveals themselves by presenting their public key and the decrypted authorization. The server learns the RC's identity only when recovery is triggered.
- Bidirectional opacity: even a recovery contact cannot determine who else is designated as RC for the same user. They can only identify their own record by attempting decryption.
- Enumeration resistance: an attacker would need to try decrypting every `_rc` record with every known private key — a computationally expensive operation with no shortcut.

**TXT record size.** Records exceeding 255 bytes require multi-string TXT encoding. Sealed box fields (device names, RCIDs) increase record sizes. Implementations MUST handle string concatenation and SHOULD test multi-string parsing explicitly.

**Zone transfer exposure.** If the identity domain allows zone transfers (AXFR), UIDs and public keys are bulk-enumerable, but device names and RC relationships remain protected by encryption. Identity domain operators SHOULD still restrict zone transfers to authorized secondaries.

---

## 13. Zone File Examples

### 13.1 Minimal Setup (1 User)

```bind
; Identity domain: id.example.org
; Single user, one device, no recovery contact

$ORIGIN id.example.org.
$TTL 3600

; Identity provider
_idp                      TXT  "v=1;issuer=https://id.example.org"

; User: root key
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=root-2026;pk=cm9vdCBrZXkgZ29lcyBoZXJl;flag=root"

; User: device key (encrypted name, opaque kid)
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=a7f3b2c1;pk=ZGVza3RvcCBrZXk;flag=primary;device=k8Tn2pFxQm4rV7jLwBs9YhD3gCeAv6RKXJ0NfMqUcWdHb5lzSoI1EiPtGyu;enroll_sig=ZW5yb2xsLWRlc2t0b3A"
```

### 13.2 Typical Community (IDP + Users + Server)

```bind
; Identity domain: id.example.org
; IDP, two users (one with recovery contact), one server

$ORIGIN id.example.org.
$TTL 3600

; === Identity Provider ===
_idp                      TXT  "v=1;issuer=https://id.example.org"

; === User: Ryan ===
; Root key
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=root-2026;pk=cnlhbiByb290IGtleQ;flag=root"
; Device keys (encrypted names, opaque kids)
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=a7f3b2c1;pk=cnlhbiBkZXNrdG9wIGtleQ;flag=primary;device=k8Tn2pFxQm4rV7jL;enroll_sig=ZW5yb2xsLXJ5YW4tZGVza3RvcA"
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=e9d4f8a0;pk=cnlhbiBwaG9uZSBrZXk;device=Qx7mWnK4pLs8Bf2T;enroll_sig=ZW5yb2xsLXJ5YW4tcGhvbmU"
; Handle
ryan._h                   TXT  "v=1;uid=01j5a3k7pm9qwr4txyz6bn8vhe"
; Recovery contact (blind RCID — observer cannot tell who this is)
01j5a3k7pm9qwr4txyz6bn8vhe._rc  TXT  "v=1;rcid=Hx8k2Qm9Tp4vN7jLwBs3YhD6gCeAv1RK;name=a8Fk2mNx9pQ3rLvJw;window=14d;death_window=60d"

; === User: Tara ===
; Root key
01j5tara0000000000000000rc._k  TXT  "v=1;k=ed25519;kid=root-2026;pk=dGFyYSByb290IGtleQ;flag=root"
; Device key
01j5tara0000000000000000rc._k  TXT  "v=1;k=ed25519;kid=f1b2c3d4;pk=dGFyYSBsYXB0b3Aga2V5;flag=primary;device=Wm5nPqLx2Ws5Tv7j;enroll_sig=ZW5yb2xsLXRhcmEtbGFwdG9w"
; Handle
tara._h                   TXT  "v=1;uid=01j5tara0000000000000000rc"

; === Server: Community Chat ===
01j5srv7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=srv-2026;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;type=server"
```

**Server's own zone (separate DNS):**
```bind
; Zone: chat.devreg.org (operated by server owner)

$ORIGIN chat.devreg.org.
$TTL 3600

_k  TXT  "v=1;k=ed25519;kid=srv-2026;pk=c2VydmVyIGtleSBnb2VzIGhlcmU;uid=01j5srv7pm9qwr4txyz6bn8vhe"
```

### 13.3 During Active Recovery

```bind
; Ryan's account during full recovery
; Note: TTLs dropped to 300 for fast propagation

$ORIGIN id.example.org.
$TTL 300

; Root key (still published, not yet revoked)
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=root-2026;pk=cnlhbiByb290IGtleQ;flag=root"

; Device keys (contested during full recovery)
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=a7f3b2c1;pk=cnlhbiBkZXNrdG9wIGtleQ;flag=primary,contested;device=k8Tn2pFxQm4rV7jL;enroll_sig=ZW5yb2xsLXJ5YW4tZGVza3RvcA"
01j5a3k7pm9qwr4txyz6bn8vhe._k  TXT  "v=1;k=ed25519;kid=e9d4f8a0;pk=cnlhbiBwaG9uZSBrZXk;flag=contested;device=Qx7mWnK4pLs8Bf2T;enroll_sig=ZW5yb2xsLXJ5YW4tcGhvbmU"

; Account state: full recovery in progress (no 'by' field — initiator protected by blind RCID)
01j5a3k7pm9qwr4txyz6bn8vhe._s  TXT  "v=1;state=full_recovery;ts=2026-03-01T00:00:00Z;expires=2026-03-15T00:00:00Z;sig=cmVjb3Zlcnkgc2ln"

; Recovery contact (unchanged, still opaque)
01j5a3k7pm9qwr4txyz6bn8vhe._rc  TXT  "v=1;rcid=Hx8k2Qm9Tp4vN7jLwBs3YhD6gCeAv1RK;name=a8Fk2mNx9pQ3rLvJw;window=14d;death_window=60d"
```

---

## Appendix A: Complete Record Type Summary

| Record Type | DNS Label | Purpose | Key Fields |
|-------------|-----------|---------|------------|
| Identity Provider | `_idp.<domain>` | Discover SSO issuer and JWKS | `issuer`, `jwks` |
| Entity Key | `<uid>._k.<domain>` | Publish root and device keys | `k`, `kid`, `pk`, `flag`, `device` (sealed box), `enroll_sig` |
| Server Self-Key | `_k.<server-domain>` | Dual-source trust anchor | `k`, `kid`, `pk`, `uid` |
| Handle | `<handle>._h.<domain>` | Map human name to UID | `uid` |
| Migration | `<uid>._m.<domain>` | Redirect to new identity domain | `to`, `ts`, `sig` |
| Recovery Contact | `<uid>._rc.<domain>` | Designate social recovery contact | `rcid` (sealed box), `name` (sealed box), `window`, `death_window` |
| RC Change | `<uid>._rcc.<domain>` | Pending recovery contact change | `old_rcid`, `new_rcid`, `new_name`, `ts`, `effective`, `sig` |
| Account State | `<uid>._s.<domain>` | Signal non-stable account state | `state`, `ts`, `expires`, `sig` |

---

## Appendix B: Field Encoding Quick Reference

| Field Type | Encoding | Byte Size | Example |
|-----------|----------|-----------|---------|
| Public key (`pk`) | Base64url, no padding | 32 bytes raw / 43 chars encoded | `cm9vdCBrZXkgZ29lcyBoZXJl` |
| Signature (`sig`, `enroll_sig`) | Base64url, no padding | 64 bytes raw / 86 chars encoded | `c2lnbmF0dXJlIGdvZXMgaGVyZQ` |
| Sealed box (short plaintext) | Base64url, no padding | plaintext + 48 bytes overhead | `k8Tn2pFxQm4rV7jLwBs9YhD3g` |
| Sealed box (64-byte signature) | Base64url, no padding | 112 bytes raw / 150 chars encoded | `Hx8k2Qm9Tp4vN7jLwBs3YhD6g...` |
| UID | Crockford Base32 | 16 bytes raw / 26 chars encoded | `01j5a3k7pm9qwr4txyz6bn8vhe` |
| Timestamp | ISO 8601 UTC | Variable | `2026-03-01T00:00:00Z` |
| Duration | Integer + unit | Variable | `14d`, `60d`, `7d` |
| Key algorithm | String literal | — | `ed25519` |
| Version | Integer string | — | `1` |
| Flags | Comma-separated strings | — | `root`, `primary,rotate` |
