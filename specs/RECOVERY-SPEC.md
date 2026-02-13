# Recovery & Account Lifecycle — v0.5

**Status:** Draft
**Parent document:** [IDENTITY-SPEC.md](IDENTITY-SPEC.md)
**Companion documents:** [DNS-RECORDS-SPEC.md](DNS-RECORDS-SPEC.md)

This document covers what happens when things go wrong: lost devices, lost keys, compromised keys, and permanent account termination. Each recovery scenario gets its own section with step-by-step flows, edge cases, and security analysis.

Recovery contact relationships are privacy-protected using **blind RCIDs** — sealed box encryption that hides the RC's identity from DNS observers. The RC proves their status by decrypting the sealed box at recovery time. See [DNS-RECORDS-SPEC.md §7](DNS-RECORDS-SPEC.md#7-recovery-contact-_rc) for the cryptographic details.

---

## 1. Overview

### 1.1 Recovery Philosophy

Identity recovery is the hardest problem in decentralized identity. The system provides **four independent recovery layers**, each addressing a different failure mode:

1. **Device cache** — fastest path, survives password loss.
2. **SSO encrypted backup** — survives device loss, requires password.
3. **Cold backup key** — survives everything, requires physical backup + passphrase.
4. **Social recovery** — survives total key loss, requires a trusted human.

The design principles:

- **No single point of failure.** Losing one layer never locks you out if another layer is intact.
- **Social recovery as last resort.** When all key material is gone, a trusted contact can vouch for you — but with mandatory waiting periods to prevent abuse.
- **Time is a defense mechanism.** Grace periods give the real owner time to notice and cancel unauthorized recovery attempts.
- **Recovery contacts are scoped.** They can help you recover, but they cannot silently take over your identity.
- **Irreversibility is intentional.** Tombstoning an account is permanent by design — it prevents identity resurrection attacks.

### 1.2 Threat Model for Recovery

| Threat | Description | Primary Defense | Secondary Defense |
|--------|-------------|-----------------|-------------------|
| Lost device | Single device lost or stolen | Revoke device key with root key | Other devices still work |
| Lost all devices | All devices lost simultaneously | SSO encrypted backup OR cold backup key | Social recovery (full recovery) |
| Lost backup | Cold backup key destroyed or forgotten | Device keys still work; SSO backup still works | Social recovery for root key rotation |
| Compromised root key | Attacker has root key | Recovery contact can initiate recovery | 7-day RC change delay prevents silent RC swap |
| Compromised device | Attacker has one device key | Revoke specific device key | Other device keys unaffected |
| Compromised RC | Recovery contact is malicious | Grace period + cancellation by real owner | Future: M-of-N threshold recovery |
| Deceased user | User permanently gone | Social death via recovery contact | 60-day grace period as safety net |
| Coerced recovery | Attacker forces RC to initiate recovery | Grace period gives real owner time to cancel | Public state visibility alerts community |

### 1.3 Recovery Scenario Comparison Table

| Scenario | Who Initiates | What's Lost | Grace Period | Cancelable By | Outcome |
|----------|--------------|-------------|--------------|---------------|---------|
| Device revocation | User (root key) | One device | None | N/A | Single device key revoked |
| Root key rotation | User (device key) + RC | Root key | 14d (configurable) | Any device key | New root key, devices unchanged |
| Full recovery | RC only | All keys | 14d (configurable) | Root key only | Full key reset |
| Social death | RC only | User is gone | 60d (configurable) | Root key or any device key | Permanent tombstone |

---

## 2. Key Storage Layers

### 2.1 The 4-Layer Model

| Layer | Storage | Protected By | Survives | Contains |
|-------|---------|-------------|----------|----------|
| 1 | Device keychain/keystore | OS biometric / device PIN | Device loss: NO | Device private key |
| 2 | SSO server (encrypted) | User password (Argon2id) | SSO death: NO | Encrypted device private key |
| 3 | Cold backup key (BIP38-style) | Passphrase (Argon2id) | Everything | Root private key |
| 4 | Recovery contacts (social) | Out-of-band verification + grace period | Everything (no key material needed) | No key material — resets identity |

Layers 1-3 are independently sufficient to recover key material. Layer 4 (social recovery) doesn't recover existing keys — it resets the identity through a trusted contact.

### 2.2 Layer 1 — Device Cache

**What:** Device private key stored in the OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service) or an encrypted local file.

**Protected by:** Device biometrics (fingerprint, face) or local PIN.

**Fast path:** User taps fingerprint -> device key is unlocked -> challenge-response -> JWT -> logged in.

**When it fails:** Device lost, stolen, or factory reset. The key is gone with the device.

**Recovery from Layer 1 failure:** Use another device (Layer 1 on a different machine), SSO backup (Layer 2), cold backup (Layer 3), or social recovery (Layer 4). Then revoke the lost device's key using the root key.

### 2.3 Layer 2 — SSO Encrypted Backup

**What:** The SSO stores an encrypted blob it cannot read. This contains the encrypted device private key for the device that registered via that SSO.

**Format:**
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
  "ciphertext": "<base64url, AES-256-GCM encrypted device private key + auth tag>"
}
```

**Encryption:** `Argon2id(password, salt)` -> 256-bit key -> `AES-256-GCM(key, nonce, device_private_key)`.

**Rate limiting:** The server enforces rate limiting on retrieval attempts (e.g., 5 attempts per hour, exponential backoff) to resist online brute-force.

**When it fails:** SSO server is down or decommissioned, or user forgets their password.

### 2.4 Layer 3 — Cold Backup Key (BIP38-Style)

**What:** A printable recovery string encoding the root private key, generated at registration.

**Example:**
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
1. User enters backup string + passphrase.
2. Client decodes Base58Check, validates checksum.
3. Client derives key via Argon2id with embedded params.
4. Client decrypts root private key.
5. User has full identity authority — can enroll new devices, revoke old ones, register with any SSO.

**Passphrase guidance:**
- Minimum 12 characters recommended.
- Argon2id with aggressive params (256MB memory) to resist offline brute-force.
- Optional: offer BIP39-style mnemonic (24 words) as alternative encoding.

**When it fails:** Physical backup lost, destroyed, or passphrase forgotten. This is the "break glass" layer — users should store it like they'd store a safe deposit box key.

### 2.5 When Each Layer Is Sufficient

**"I lost my phone but have my laptop"** -> Layer 1 (other device). Revoke lost device key with root key.

**"I lost all my devices but remember my SSO password"** -> Layer 2. Decrypt backup, get device key, re-enroll.

**"I lost everything but have my cold backup string"** -> Layer 3. Decrypt root key, enroll new devices, revoke old ones.

**"I lost literally everything"** -> Layer 4 (social recovery). Recovery contact initiates full recovery. 14-day grace period. Complete key reset.

**"I lost my root key but still have working devices"** -> Layer 4 (root key rotation). Recovery contact + device key co-sign. 14-day grace period. New root key, existing devices unchanged.

---

## 3. Recovery Contacts

### 3.1 What Is a Recovery Contact

A recovery contact is another user in the system whom you trust to help you recover your identity if you lose all your keys. Think of it like an emergency contact on a medical form — someone who can vouch for your identity through an out-of-band channel (phone call, in-person meeting).

**Privacy:** Recovery contact relationships are hidden in DNS using **blind RCIDs** — sealed box encryption that conceals the RC's identity from everyone except the RC themselves and the user (who can decrypt the friendly name). The identity server does not know who your recovery contact is until recovery is actually triggered. Even the RC cannot see who else is designated. See [DNS-RECORDS-SPEC.md §7](DNS-RECORDS-SPEC.md#7-recovery-contact-_rc) for the cryptographic details.

Recovery contacts can:
- Co-sign a root key rotation (when you have a working device but lost your root key).
- Initiate a full recovery (when you've lost all key material).
- Initiate a social death declaration (when you're permanently gone).

Recovery contacts **cannot**:
- Access your private keys.
- Authenticate as you.
- Silently take over your identity (grace periods and cancellation mechanisms prevent this).
- Determine who else is designated as a recovery contact for the same user.

### 3.2 Designating a Recovery Contact

A user designates another user as their recovery contact by creating a **blind RCID** — a sealed box containing the root key's authorization signature, encrypted to the RC's public key. The designation is published as a DNS record.

**Abbreviated record** (see [DNS-RECORDS-SPEC.md §7](DNS-RECORDS-SPEC.md#7-recovery-contact-_rc) for full field table):
```
<uid>._rc.<domain>  TXT  "v=1;rcid=<base64url>;name=<base64url>;window=14d;death_window=60d"
```

**RCID construction:**
1. User knows the RC's Ed25519 public key.
2. Construct authorization message with null-byte separators: `msg = "recover" 0x00 uid 0x00 rc_pk 0x00 window 0x00 death_window 0x00 timestamp`
3. Root key signs authorization: `auth_sig = Sign(root_key, msg)` (64 bytes)
4. Seal to the RC's X25519 public key: `rcid = SealedBox(rc_x25519_pk, auth_sig)` (112 bytes)
5. Optionally encrypt a friendly name (max 64 bytes UTF-8): `name = SealedBox(user_root_x25519_pk, "Tara")`

- `rcid` = sealed box containing the root key's authorization signature, encrypted to the RC's public key. Only the RC can decrypt.
- `name` = sealed box containing a friendly name for the RC, encrypted to the user's root public key. Only the user can decrypt.
- `window` = waiting period for recovery operations (default 14d)
- `death_window` = waiting period for death declaration (default 60d)
- Multiple recovery contacts allowed (future: M-of-N threshold, see §9)

**What an observer sees:** An opaque `rcid` blob and an opaque `name` blob. No UID, no public key, no identifiable information about the recovery contact.

### 3.3 Changing a Recovery Contact

Changing recovery contacts has a mandatory **7-day waiting period**. This prevents a compromised root key from silently swapping the recovery contact before triggering a fake recovery.

**Abbreviated record** (see [DNS-RECORDS-SPEC.md §8](DNS-RECORDS-SPEC.md#8-recovery-contact-change-_rcc) for full field table):
```
<uid>._rcc.<domain>  TXT  "v=1;old_rcid=<base64url>;new_rcid=<base64url>;new_name=<base64url>;ts=<timestamp>;effective=<timestamp+7d>;sig=<base64url>"
```

The `old_rcid` matches the existing `_rc` record's `rcid` value. The `new_rcid` is a fresh sealed box for the replacement RC. The server identifies which RC is being replaced by matching the `old_rcid` value — no UIDs are involved.

### 3.4 The 7-Day Change Delay

**Why 7 days?** It's a compromise between security and convenience:
- Short enough that it doesn't prevent legitimate changes.
- Long enough that the real owner or existing recovery contact will likely notice.

**During the 7-day period:**
- The user notifies both old and new recovery contacts **out-of-band** (the identity server does not know their identities due to blind RCIDs).
- The old RC can detect the pending change by checking for `_rcc` records and recognizing their `old_rcid` value.
- Any device key OR root key can cancel the change.
- The old recovery contact retains full recovery powers until the change takes effect.

**After 7 days:** The `_rc` record matching `old_rcid` is replaced with a new record containing `new_rcid` and `new_name`. The `_rcc` record is removed.

**Attack scenario walkthrough:**

1. Attacker compromises Alice's root key.
2. Attacker publishes a recovery contact change: swap Tara (real RC) for Mallory (attacker's accomplice). The `_rcc` record appears in DNS.
3. Day 0: `_rcc` record published. Tara, monitoring `_rcc` records for Alice, detects the pending change by recognizing her `old_rcid`.
4. Day 1-2: Tara calls Alice. Alice didn't request this.
5. Day 2: Alice uses any device key to cancel the change.
6. Result: Attack foiled. Without the 7-day delay, Mallory would have been active as RC before anyone noticed.

### 3.5 Blocking Rules During Active Recovery

If the account is in **any active recovery state** (`root_rotation`, `full_recovery`, `death`), recovery contact changes are **BLOCKED** until the recovery state resolves. The identity server MUST reject `_rcc` publication during these states.

This prevents an attacker from changing the recovery contact while a legitimate recovery is in progress.

---

## 4. Account State Model

### 4.1 States and DNS Representation

Accounts can be in one of five states. Only non-stable states have a DNS record.

| State | DNS Record | Description |
|-------|-----------|-------------|
| `stable` | *(no `_s` record)* | Normal operation. Default state. |
| `root_rotation` | `_s` with `state=root_rotation` | Root key being replaced. Device keys unchanged. |
| `full_recovery` | `_s` with `state=full_recovery` | Full identity reset in progress. All device keys contested. |
| `death` | `_s` with `state=death` | Account termination in progress. Grace period active. |
| `tombstone` | `_s` with `state=tombstone` | Permanently dead. Irreversible. |

See [DNS-RECORDS-SPEC.md §9](DNS-RECORDS-SPEC.md#9-account-state-_s) for full record format and field table.

### 4.2 State Transition Diagram

```
                           +---------+
                           | stable  |<------------------------------+
                           +----+----+                               |
                                |                                    |
              +-----------------+------------------+                 |
              |                 |                   |                 |
              v                 v                   v                 |
     +--------+------+  +------+--------+  +-------+-----+          |
     | root_rotation |  | full_recovery |  |    death    |          |
     | (14d grace)   |  | (14d grace)   |  | (60d grace) |          |
     +--------+------+  +------+--------+  +-------+-----+          |
              |                 |                   |                 |
    +---------+---------+      |          +--------+--------+        |
    |                   |      |          |                 |        |
    v                   v      |          v                 v        |
 [completed]       [canceled]  |     [canceled]        [expired]     |
 New root key,     Return to   |     Return to         |            |
 devices stay      stable      |     stable            v            |
    |                   |      |          |       +---------+        |
    +----->stable<------+      |          |       |tombstone|        |
                               |          |       +---------+        |
                      +--------+--------+ |       (permanent)        |
                      |                 | |                           |
                      v                 v |                           |
                 [completed]       [canceled]                         |
                 Full key reset    Return to                          |
                      |            stable                             |
                      +----->stable<---+-----------------------------+
```

**Rules:**
- Only one non-stable state can be active at a time.
- `stable` is the only state from which recovery can be initiated.
- `tombstone` is permanent — no transitions out.
- RC changes are blocked during any non-stable state.

### 4.3 State Transition Summary Table

| State | Triggered By | Grace Period | Cancelable By | On Completion | On Cancellation |
|-------|-------------|--------------|---------------|---------------|-----------------|
| `root_rotation` | User (device key) + RC | 14d (configurable) | Any device key | New root key; devices unchanged | Return to `stable` |
| `full_recovery` | RC only | 14d (configurable) | Root key only | Full key reset | Return to `stable`; `contested` flags removed |
| `death` | RC only | 60d (configurable) | Root key or any device key | Transition to `tombstone` | Return to `stable` |
| `tombstone` | Automatic (after `death` grace period) | N/A | N/A (permanent) | N/A | N/A |

---

## 5. Scenario: Root Key Rotation

### 5.1 When This Applies

The user has at least one working device but has lost access to their root key. Common causes:
- Cold backup string lost or destroyed.
- Cold backup passphrase forgotten.
- Root key storage medium degraded.

The user can still authenticate day-to-day (device keys work), but cannot perform management operations (enroll new devices, revoke old ones, change recovery contacts).

### 5.2 Preconditions

- User has at least one active, non-revoked device key.
- User has a designated recovery contact with an active key.
- Account is in `stable` state (no other recovery in progress).

### 5.3 Step-by-Step Flow

1. **User initiates:** Publishes a root rotation request signed with their device key.
2. **Out-of-band verification:** User contacts recovery contact through a separate channel (phone call, in-person meeting) to confirm the request is legitimate.
3. **RC proves authorization:** Recovery contact fetches the user's `_rc` records, decrypts the sealed box RCID with their private key to extract the root authorization signature, then presents their public key + the authorization signature + a signed request to the identity server. The server verifies both the root key authorization and the RC's key ownership. See [DNS-RECORDS-SPEC.md §7.4](DNS-RECORDS-SPEC.md#74-rc-verification-flow) for the full verification flow.
4. **State change:** Identity server sets account state to `root_rotation` with the configured grace period (default 14 days).
5. **Grace period:** All existing device keys remain active. Daily operations continue normally.
6. **Grace period expires (no cancellation):**
   - User generates new root Ed25519 keypair (from new BIP-39 seed).
   - Recovery contact signs authorization for the new root key.
   - Old root key is revoked in DNS (`flag=revoked`).
   - New root key is published with `flag=root`.
   - All existing device keys remain valid (their enrollment sigs are historical).
7. **User generates new cold backup string** encoding the new root private key.
8. **Account returns to `stable` state.**

### 5.4 Sequence Diagram

```
User (device key)        Recovery Contact          Identity Server
  |                           |                            |
  | Root rotation request     |                            |
  | sig=Sign(device_key,...)  |                            |
  |-------------------------------------------------------->|
  |                           |                            |
  | [out-of-band: phone call] |                            |
  | "I need to rotate my root"|                            |
  |~~~~ ~~~~ ~~~~ ~~~~ ~~~~>  |                            |
  |                           |                            |
  |                           | Fetch _rc records          |
  |                           | Decrypt RCID (sealed box)  |
  |                           | -> extract root auth sig   |
  |                           |                            |
  |                           | Present: my_pk + root_sig  |
  |                           | + Sign(rc_key, request)    |
  |                           |--------------------------->|
  |                           |                            |
  |                           |  Verify root_sig (RC auth) |
  |                           |  Verify rc_key (ownership) |
  |                           |                            |
  |                     State -> root_rotation              |
  |                     Grace period: 14 days               |
  |                     (cancelable by any device key)      |
  |                           |                            |
  |  ... 14 days pass, no cancellation ...                 |
  |                           |                            |
  | Generate new root keypair |                            |
  |                           |                            |
  |                           | Sign new root authorization|
  |                           |--------------------------->|
  |                           |                            |
  | Publish new root key      |                            |
  |-------------------------------------------------------->|
  |                           |                            |
  |                     Old root -> flag=revoked            |
  |                     New root -> flag=root               |
  |                     Device keys unchanged               |
  |                     State -> stable                     |
```

### 5.5 What Happens to Existing Sessions

During root key rotation:
- **Active sessions continue normally.** Device keys are unaffected.
- **New device enrollments are blocked** (no valid root key to sign them) until the new root key is published.
- **Relying parties see `root_rotation` state** and MAY display a notice, but SHOULD NOT restrict access.

After rotation completes:
- All existing sessions continue.
- New devices can be enrolled using the new root key.
- Existing enrollment signatures are still valid (they were signed by the root key that was valid at enrollment time).

### 5.6 Edge Cases

**RC is offline during grace period:** The rotation request can be submitted whenever the RC is available. The grace period starts when the RC co-signs, not when the user initiates. If the RC becomes unavailable after co-signing, the rotation proceeds automatically after the grace period.

**User finds old root key mid-grace:** The user can cancel the rotation using any device key, then use the recovered root key normally. No harm done — cancellation simply returns to `stable`.

**User has no recovery contact:** Root key rotation requires a recovery contact. Without one, the user must rely on Layers 1-3 for key material recovery. This is why recovery contact designation is recommended at registration.

**RC and user disagree on legitimacy:** If the recovery contact suspects the request is fraudulent (e.g., social engineering), they should refuse to co-sign. The user would need to convince the RC through stronger out-of-band verification.

**Multiple devices, one compromised:** If the user suspects one device is compromised, they should revoke that device key using the root key (if available) or proceed with root key rotation if the root key is what's compromised. The compromised device can cancel the rotation during the grace period — this is intentional, as the attacker having a device key means the "lost everything" scenario (full recovery) may be more appropriate.

### 5.7 Security Considerations

**Attacker with compromised device key:** Cannot initiate root rotation alone — also needs the recovery contact to co-sign. Social engineering the RC is the primary attack vector; strong out-of-band verification mitigates this.

**Attacker with compromised root key:** Would not use root rotation (they have the root key). They would more likely try to enroll rogue devices or change the recovery contact (which has its own 7-day delay).

**Cancellation risk:** Any device key can cancel. If an attacker has a device key, they could cancel legitimate rotations. The user would need to revoke the compromised device key first — but that requires the root key they've lost. In this case, full recovery (§6) may be necessary.

---

## 6. Scenario: Full Recovery

### 6.1 When This Applies

The user has lost **all** key material — no devices, no SSO backup, no cold backup. This is the worst-case key loss scenario. The user still exists as a person and can prove their identity through out-of-band channels to their recovery contact.

Common causes:
- House fire, theft of all devices.
- Total amnesia on passwords + lost cold backup.
- All devices and backups destroyed simultaneously.

### 6.2 Preconditions

- User has a designated recovery contact with an active key.
- Recovery contact can verify the user's identity out-of-band (phone call, video call, in-person meeting).
- Account is in `stable` state.

### 6.3 Step-by-Step Flow

1. **Out-of-band contact:** User contacts recovery contact through a non-digital channel (phone call, in-person).
2. **RC proves authorization and initiates:** Recovery contact fetches the user's `_rc` records, decrypts the RCID sealed box to extract the root authorization signature, then presents their public key + authorization signature + signed recovery request. The server verifies both proofs. See [DNS-RECORDS-SPEC.md §7.4](DNS-RECORDS-SPEC.md#74-rc-verification-flow).
3. **State change:** Identity server sets account state to `full_recovery`.
4. **Device keys contested:** All existing device keys are marked `contested` in DNS.
5. **Grace period (14 days):** Only the root key can cancel. If the user actually has the root key, the "lost everything" claim was false.
6. **Grace period expires (no cancellation):**
   - Recovery contact signs authorization for a new root key.
   - User generates new root Ed25519 keypair (from new BIP-39 seed).
   - User generates new first device Ed25519 keypair.
   - New root key signs enrollment for the new device key.
   - All old keys (root + all device keys) are revoked.
   - New root key and device key are published to DNS.
7. **User generates new cold backup string** and stores new device key in keychain.
8. **Account returns to `stable` state.**

### 6.4 Sequence Diagram

```
User (no keys)           Recovery Contact          Identity Server
  |                           |                            |
  | [out-of-band: phone call] |                            |
  | "I've lost everything"    |                            |
  |~~~~ ~~~~ ~~~~ ~~~~ ~~~~>  |                            |
  |                           |                            |
  |                           | Fetch _rc records          |
  |                           | Decrypt RCID (sealed box)  |
  |                           | -> extract root auth sig   |
  |                           |                            |
  |                           | Present: my_pk + root_sig  |
  |                           | + Sign(rc_key, request)    |
  |                           |--------------------------->|
  |                           |                            |
  |                           |  Verify root_sig (RC auth) |
  |                           |  Verify rc_key (ownership) |
  |                           |                            |
  |                     State -> full_recovery              |
  |                     All device keys -> contested        |
  |                     Grace period: 14 days               |
  |                     (cancelable by root key ONLY)       |
  |                           |                            |
  |  ... 14 days pass, no cancellation ...                 |
  |                           |                            |
  |                           | Sign new root authorization|
  |                           |--------------------------->|
  |                           |                            |
  | Generate new root keypair |                            |
  | Generate new device keypair|                           |
  | Root signs device enrollment|                          |
  |                           |                            |
  | Publish new keys          |                            |
  |-------------------------------------------------------->|
  |                           |                            |
  |                     All old keys -> revoked             |
  |                     New root + device published         |
  |                     State -> stable                     |
```

### 6.5 Contested Device Keys — Behavior and UX

During `full_recovery`, all existing device keys are marked `contested`. This is a signal to relying parties that these keys may belong to an attacker, not the real user.

**What relying parties SHOULD do:**

| Action Category | Behavior During Contested State |
|----------------|-------------------------------|
| Read-only operations | Allow normally (reading messages, viewing channels) |
| Standard operations | Allow with warning banner ("This user's identity is being recovered") |
| Sensitive operations | Require additional verification or block (admin actions, payment, key changes) |
| Display to others | Show visual indicator that the user's identity is contested |

**What "reduced trust" means in practice:**
- Chat messages from contested keys display with a warning indicator (e.g., yellow shield icon).
- Other users see: "Ryan's identity is being recovered. Messages from this account may not be from Ryan."
- Server admin operations from contested keys are blocked.
- New server connections during contested state should show a prominent warning.

**Why only root key can cancel:** If the user "lost everything," their device keys may be in an attacker's hands. Allowing device keys to cancel would let the attacker (who stole the devices) block legitimate recovery. The root key is the ultimate proof of identity.

### 6.6 What If Root Key Surfaces During Grace Period

If someone produces the root key during the grace period, it means one of:
- The user found their cold backup (legitimate — cancel recovery, return to normal).
- An attacker has the root key (possible — but canceling recovery actually protects the account by reverting to the state the attacker already controls, buying time for investigation).

Either way, cancellation is the correct action: it preserves the status quo while the situation is investigated. The user and recovery contact should communicate out-of-band to determine what happened.

### 6.7 Edge Cases

**RC initiates recovery fraudulently:** The 14-day grace period gives the real owner time to produce their root key and cancel. If the real owner truly has no keys, they have no way to cancel — this is the fundamental trust placed in the recovery contact. Future M-of-N threshold recovery (§9) mitigates this.

**User finds a device during grace period:** Found device keys cannot cancel full recovery (only root key can). The user should use the found device to communicate with the community that they're alive, and attempt to locate their cold backup to produce the root key.

**RC becomes unavailable after initiating:** The grace period runs automatically. After it expires, the user can complete recovery without further RC involvement (the RC's initial signature is sufficient authorization). If the user cannot complete recovery (e.g., cannot generate new keys due to technical issues), the state eventually returns to `stable` after a timeout (implementation-defined, recommended 30 days after grace period).

**Concurrent attack — attacker has devices, RC helps real user:** The contested flag warns the community. The attacker's device keys work but with reduced trust. After recovery completes, all old keys (including the attacker's devices) are revoked. Clean slate.

### 6.8 Security Considerations

**Social engineering the RC:** The primary attack vector. A determined attacker could impersonate the user to the recovery contact. Mitigations: out-of-band verification should use pre-established knowledge (shared secrets, visual identification), not just "I'm calling from Ryan's number."

**Race condition — attacker with root key:** If an attacker has the root key and the RC initiates recovery, the attacker can cancel. The user and RC should coordinate: if cancellation happens and the user didn't do it, the root key is compromised. The RC should attempt recovery again (and the user should investigate the root key compromise through other channels).

**Post-recovery cleanup:** After full recovery, the user should immediately:
1. Generate and securely store a new cold backup.
2. Designate a recovery contact (may be the same or different).
3. Report any suspicious activity during the contested period.

---

## 7. Scenario: Social Death

### 7.1 When This Applies

A recovery contact believes the user is **permanently gone** — deceased, permanently incapacitated, or otherwise permanently unable to manage their identity. This is the mechanism for graceful account termination when the account holder can never return.

This is NOT for:
- Temporary absence (users can simply not log in — no action needed).
- Account deactivation (not supported in this spec — the user just stops using it).
- Banning or moderation (server-side policy, not identity-layer).

### 7.2 Preconditions

- A recovery contact exists for the account.
- Recovery contact has a genuine, good-faith belief that the user is permanently gone.
- Account is in `stable` state.

### 7.3 Step-by-Step Flow

1. **RC decides to act:** Recovery contact determines (through real-world information) that the user is permanently gone.
2. **RC proves authorization and initiates:** Recovery contact fetches the user's `_rc` records, decrypts the RCID sealed box to extract the root authorization signature, then presents their public key + authorization signature + signed death declaration. The server verifies both proofs. See [DNS-RECORDS-SPEC.md §7.4](DNS-RECORDS-SPEC.md#74-rc-verification-flow).
3. **State change:** Identity server sets account state to `death`.
4. **Grace period (60 days):** Existing sessions continue. No new device enrollments. The `death` state is visible to all relying parties.
5. **Grace period expires (no cancellation):**
   - State becomes `tombstone` — permanent, irreversible.
   - All keys are revoked.
   - UID is burned — can never be re-enabled.
   - DNS records become tombstone markers.
6. **Tombstone persists indefinitely.**

### 7.4 Sequence Diagram

```
                         Recovery Contact          Identity Server
                              |                            |
                              | Fetch _rc records          |
                              | Decrypt RCID (sealed box)  |
                              | -> extract root auth sig   |
                              |                            |
                              | Present: my_pk + root_sig  |
                              | + Sign(rc_key, death_decl) |
                              |--------------------------->|
                              |                            |
                              |  Verify root_sig (RC auth) |
                              |  Verify rc_key (ownership) |
                              |                            |
                        State -> death                     |
                        60-day grace period                 |
                        (cancelable by root key             |
                         or ANY device key)                 |
                              |                            |
  ... 60 days, no cancellation ...                         |
                              |                            |
                        State -> tombstone                  |
                        All keys revoked                    |
                        UID permanently burned              |
                              |                            |
                        Tombstone record persists           |
                        indefinitely                        |
```

### 7.5 Grace Period Detail

**During the 60-day grace period:**

| What Works | What's Blocked |
|-----------|---------------|
| Existing authenticated sessions continue | New device enrollments |
| Existing device keys authenticate normally | New server connections (implementation-dependent) |
| Reading messages, participating in channels | Recovery contact changes |
| Other users can see the `death` state | New recovery operations |

**Visibility:** The `death` state is published in DNS and visible to all relying parties. Servers SHOULD:
- Display a notice: "This account has been declared deceased. If you are the account holder, log in to cancel."
- Continue allowing existing sessions to function (in case the declaration is erroneous).
- Optionally send a notification to the user through all active sessions.

### 7.6 Tombstone Permanence

Once an account reaches `tombstone`, it is **permanent and irreversible**:

- **UID is burned.** The UID can never be re-registered, even by the same person. This prevents identity resurrection attacks where someone re-claims a dead user's UID.
- **Keys are revoked.** All root and device keys are flagged `revoked` in DNS. Eventually, the key records may be removed, but the tombstone `_s` record persists.
- **Handle is released.** The `_h` mapping is removed. Another user could claim the same handle with a different UID.
- **Migration records are preserved.** If the user had migrated from another domain, the `_m` records remain as historical pointers.

**Long-term DNS footprint:** Over time, an identity domain operator may clean up revoked key records, but the tombstone `_s` record SHOULD be retained indefinitely (or at least for several years) to prevent UID reuse.

**If the user comes back:** If the user was not actually dead (e.g., declared dead due to prolonged absence, then returns), they must start over with a new UID. Their old identity is permanently gone. This harsh policy exists to prevent disputes over identity ownership — once tombstoned, there is no ambiguity.

### 7.7 Edge Cases

**RC declares death prematurely:** The 60-day grace period is intentionally long. Any proof of life (authenticating with any device key or root key) cancels the process. The real user just needs to log in once.

**Multiple RCs disagree:** If multiple recovery contacts are designated (future: M-of-N), death declaration would require threshold agreement. In the current single-RC model, the single RC has unilateral power.

**RC dies before grace period ends:** The death declaration runs automatically. No further RC involvement is needed once initiated. After the grace period, the tombstone is applied automatically.

**User is incapacitated but has family/friends with device access:** Anyone who can authenticate with the user's device key can cancel the death declaration. This is intentional — the bar for "proof of life" is deliberately low.

**Legal considerations:** This spec defines technical account termination, not legal death. Communities may layer additional policies (e.g., requiring a death certificate) on top of the protocol.

### 7.8 Security Considerations

**Social death abuse:** The long grace period (60 days) and low cancellation bar (any device key or root key) make it difficult to permanently destroy someone's identity without their knowledge. Any proof of life cancels the process.

**Malicious RC:** A compromised or malicious recovery contact can initiate social death. The 60-day period is the safety net. If the user is alive and has any key, they cancel. If they truly have no keys and are alive, they need the root key (which may require locating their cold backup).

**Harassment vector:** Repeated death declarations could be used to harass a user (even though they're always cancellable). Mitigations: the identity server SHOULD rate-limit death declarations (e.g., no more than once per 90 days per RC), and the user SHOULD change their recovery contact if this occurs.

---

## 8. Device Key Rotation Lifecycle

### 8.1 4-Phase Rotation

Device key rotation follows a 4-phase lifecycle to ensure zero-downtime transitions:

```
Phase 1: STABLE       -> single device key, flag=primary, TTL=3600
Phase 2: PRE-ROTATE   -> add new device key flag=primary, old key flag=rotate, TTL=300
Phase 3: OVERLAP      -> both device keys valid, sign with new key. Duration >=2x old TTL.
Phase 4: RETIRE       -> remove old device key (or flag=revoked), TTL back to 3600
```

See [DNS-RECORDS-SPEC.md §10.2](DNS-RECORDS-SPEC.md#102-ttl-during-key-rotation) for TTL details.

**Step-by-step:**
1. Generate new device keypair.
2. Root key signs enrollment for the new device key.
3. Publish new device key with `flag=primary`. Update old key to `flag=rotate`. Drop TTL to 300.
4. Wait at least 2x the old TTL (7200s with default 3600s TTL) for all caches to expire.
5. Start signing with new key. Old key still accepted during overlap.
6. Remove old device key (or set `flag=revoked`). Return TTL to 3600.

### 8.2 Root Key Rotation vs. Device Key Rotation

These are fundamentally different operations:

| Aspect | Device Key Rotation | Root Key Rotation |
|--------|-------------------|-------------------|
| **What rotates** | One device's keypair | The identity anchor |
| **Who initiates** | User (with root key) | User (with device key) + recovery contact |
| **Authority needed** | Root key signature | Recovery contact co-signature |
| **Grace period** | None (immediate) | 14 days |
| **Impact** | One device only | Identity management capability |
| **Frequency** | Routine (recommended yearly) | Rare (only when root key is lost) |

Device key rotation is a routine maintenance operation. Root key rotation is an emergency recovery operation.

---

## 9. Future: M-of-N Threshold Recovery

The current system supports multiple recovery contact records per account. A future enhancement will support **M-of-N threshold recovery**, where:

- A user designates N recovery contacts (each as a separate `_rc` record with a blind RCID).
- Any M of them (where M <= N) must agree to initiate recovery.
- This reduces the risk of a single compromised or malicious recovery contact.

**Likely parameters:**
- Minimum N=2, recommended N=3-5.
- M = ceil(N/2) + 1 (strict majority) for full recovery and social death.
- M = 1 for root key rotation (less destructive, lower threshold appropriate).

**Privacy properties of M-of-N with blind RCIDs:**
- Each RC has their own sealed box RCID — they can only identify their own record by attempting decryption.
- RCs cannot determine who else is designated, or how many total RCs exist (they see N opaque records but can only decrypt one).
- The user can identify each RC via the encrypted `name` field (decryptable with root key).
- The identity server only learns an RC's identity when they present their authorization during recovery.

**Open questions:**
- How to handle partial signatures (some RCs sign, others don't respond within a time window).
- Whether different operations should have different thresholds.
- Coordination mechanism for multiple RCs to independently authorize without revealing each other's identity.

This section is forward-looking and not yet normative.

---

## Appendix A: Recovery Decision Tree

```
START: "I need to recover my identity"
  |
  +-- "Do I have a working device with my key?"
  |     |
  |     +-- YES: "Is the device compromised?"
  |     |    |
  |     |    +-- NO: Use the device normally.
  |     |    |      "Do I need to revoke another device?"
  |     |    |        +-- YES: Use root key to revoke. (Need root key for this.)
  |     |    |        +-- NO: Done.
  |     |    |
  |     |    +-- YES: "Do I have my root key or cold backup?"
  |     |         |
  |     |         +-- YES: Revoke compromised device key. Enroll new device.
  |     |         +-- NO: Initiate root key rotation (§5).
  |     |               Requires recovery contact.
  |     |
  |     +-- NO: "Do I have my SSO backup password?"
  |           |
  |           +-- YES: Decrypt SSO backup (Layer 2). Get device key. Re-enroll.
  |           +-- NO: "Do I have my cold backup string + passphrase?"
  |                 |
  |                 +-- YES: Decrypt root key (Layer 3).
  |                 |        Enroll new devices. Revoke old ones.
  |                 |
  |                 +-- NO: "Do I have a recovery contact?"
  |                       |
  |                       +-- YES: Initiate full recovery (§6).
  |                       |        14-day grace period. Complete key reset.
  |                       |
  |                       +-- NO: Identity is lost. Create a new identity.
  |                              (This is why recovery contacts are recommended.)
```

---

## Appendix B: Recovery DNS Records Quick Reference

| Record | Label | Key Fields | Purpose |
|--------|-------|-----------|---------|
| Recovery Contact | `<uid>._rc.<domain>` | `rcid` (sealed box), `name` (sealed box), `window`, `death_window` | Designate trusted RC (blind — identity hidden) |
| RC Change | `<uid>._rcc.<domain>` | `old_rcid`, `new_rcid`, `new_name`, `effective`, `sig` | Pending RC change (7-day waiting period) |
| Account State | `<uid>._s.<domain>` | `state`, `ts`, `expires`, `sig` | Signal recovery state (no `by` field — initiator identity protected) |
| Tombstone | `<uid>._s.<domain>` | `state=tombstone`, `ts` | Permanent death marker |

See [DNS-RECORDS-SPEC.md](DNS-RECORDS-SPEC.md) for full field tables and examples.
