# IRC CAP `meatspeakvoice` — Voice Extension Spec v0.1

**Status:** Draft
**Goal:** Extend IRC with real-time voice channels using an SFU (Selective Forwarding Unit) architecture. Control plane over IRC, data plane over encrypted UDP.

---

## 1. Architecture: Selective Forwarding Unit (SFU)

The server receives each speaker's audio stream, decrypts the transport layer, optionally performs silence detection, re-encrypts, and forwards individually to all listeners. No server-side mixing. Clients mix locally.

**Benefits of client-side mixing:**
- Per-user volume control
- Spatial audio rendering
- Priority speaker ducking
- No server CPU cost for mixing

### 1.1 Encryption Modes

Two encryption modes per channel, controlled by channel mode:

| Mode | Channel Mode | Server Sees Audio | Silence Detection | Logging | Use Case |
|------|-------------|-------------------|-------------------|---------|----------|
| Transport (default) | `+V` | Yes | Yes | Optional | General use, gaming |
| E2E | `+V +E` | No | No | No | Privacy-sensitive channels |

Both modes always have transport encryption (client-server). E2E adds an inner encryption layer with a group symmetric key that the server never sees.

---

## 2. Control Plane (IRC Commands)

All voice control happens over the existing IRC TCP connection.

### 2.1 Capability

**New CAP:** `meatspeakvoice`

Clients negotiate this capability via standard IRCv3 `CAP REQ :meatspeakvoice`.

### 2.2 VOICE Command

```
VOICE JOIN #channel                  → join voice in channel
VOICE LEAVE #channel                 → leave voice
VOICE MUTE [#channel] [nick]        → mute self (no args) or other (with nick, requires op)
VOICE UNMUTE [#channel] [nick]      → unmute
VOICE DEAF [#channel]               → deafen self
VOICE UNDEAF [#channel]             → undeafen
VOICE WHISPER #channel nick [nick]  → whisper to specific users (private voice)
VOICE SHOUT #channel                → broadcast across linked channels
VOICE PRIORITY #channel nick        → set priority speaker (requires op)
VOICE MEDIA #channel screen         → start screen/media share (v1 signaling, impl optional)
VOICE CODECS #channel               → query supported codecs
VOICE RECORD #channel start|stop    → signal recording state to channel
VOICE KEY #channel nick :base64url  → distribute E2E group key (encrypted to recipient's X25519 pubkey)
VOICE REKEY #channel                → trigger group key rotation (member left, key compromised)
```

### 2.3 Channel Modes

```
+V  → voice-enabled channel
+S  → stage channel (speaker/audience model, hand-raise)
+E  → E2E encryption for voice (server cannot inspect audio, no silence detection, no logging)
```

### 2.4 Numeric Replies

```
900  → voice session info    :server 900 nick #channel udp=host:port token=<token> ssrc=<id> mode=transport|e2e
901  → voice user list       :server 901 nick #channel :nick1,nick2,nick3
902  → spatial audio config  :server 902 nick #channel model=inverse_square falloff=50.0
903  → codec list            :server 903 nick #channel :opus/48000/2
904  → stage speaker list    :server 904 nick #channel :speaker1,speaker2
905  → whisper established   :server 905 nick #channel :target1,target2
```

### 2.5 VOICESTATE Messages

Server broadcasts voice state changes to all users in the channel:

```
:nick!uid@host VOICESTATE #channel joined
:nick!uid@host VOICESTATE #channel left
:nick!uid@host VOICESTATE #channel muted
:nick!uid@host VOICESTATE #channel unmuted
:nick!uid@host VOICESTATE #channel deafened
:nick!uid@host VOICESTATE #channel undeafened
:nick!uid@host VOICESTATE #channel speaking
:nick!uid@host VOICESTATE #channel stopped
:nick!uid@host VOICESTATE #channel recording
:nick!uid@host VOICESTATE #channel not_recording
:nick!uid@host VOICESTATE #channel priority
```

---

## 3. Data Plane (UDP)

Separate encrypted UDP stream for audio data. Negotiated via `VOICE JOIN` response (900 numeric).

### 3.1 Packet Structure

```
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────────────┐
│ version  │ type     │ flags    │ ssrc     │ sequence │ timestamp│ payload          │
│ 1 byte   │ 1 byte   │ 1 byte   │ 4 bytes  │ 2 bytes  │ 4 bytes  │ variable         │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────────────┘
```

**Total header:** 13 bytes.

**Outer encryption:** XChaCha20-Poly1305 transport encryption (24-byte nonce prepended to encrypted packet).

Server behavior on receipt:
- Decrypts transport layer, reads header for routing
- If `flags.E2E` is set: payload is opaque (E2E encrypted with group key), forward without inspection
- If `flags.E2E` is clear: payload is plaintext Opus, server MAY inspect for silence detection

### 3.2 Packet Types

```
0x01  Audio        Opus frame(s)
0x02  Keepalive    Empty payload, for NAT traversal + latency measurement
0x03  MediaHeader  Codec/format negotiation for media streams
```

### 3.3 Flags Byte

```
bit 0: E2E      — payload is encrypted with group symmetric key (server cannot read)
bit 1: Spatial   — spatial audio data (12 bytes) appended after audio payload
bit 2: Priority  — sender is priority speaker (server may use for forwarding hints)
bit 3-7: reserved (must be 0)
```

### 3.4 Spatial Audio Data

When `flags.Spatial` is set, 12 bytes are appended after the audio payload:

```
x: float32  (4 bytes, little-endian) — left/right
y: float32  (4 bytes, little-endian) — up/down
z: float32  (4 bytes, little-endian) — forward/back
```

Game clients set `flags.Spatial` and append position data. Non-game clients omit it. Receivers with spatial audio support render via HRTF. Receivers without spatial support mix normally (ignore position data).

### 3.5 SSRC (Synchronization Source)

4-byte identifier assigned per voice session. Each speaker gets a unique SSRC. Clients use SSRC to associate UDP streams with IRC nicks. Mapping is provided in:
- 900 numeric on `VOICE JOIN`
- `VOICESTATE` messages when users join/leave

---

## 4. Encryption

### 4.1 Transport Layer (Always Active)

- Identity keys are Ed25519 (from identity spec)
- Convert to X25519 for key agreement: `crypto_sign_ed25519_pk_to_curve25519` (libsodium)
- Session key derived via X25519 Diffie-Hellman between client and server
- Packets encrypted with XChaCha20-Poly1305 (24-byte nonce, no nonce-reuse concerns)
- Session token from `VOICE JOIN` response (900 numeric) used for initial UDP authentication

### 4.2 E2E Layer (Channel Mode +E)

- Group symmetric key: 256-bit, randomly generated
- Generated by channel op or first voice joiner
- Distributed to each member via `VOICE KEY` command, encrypted to recipient's X25519 public key
- Audio payload encrypted with XChaCha20-Poly1305 using group key before transport wrapping
- Key rotated via `VOICE REKEY` when a member leaves (forward secrecy for departed members)
- Server sees routing headers (version, type, flags, ssrc, sequence, timestamp) but cannot read audio content
- Server operators MAY disallow `+E` mode via server config if they require logging capability

### 4.3 E2E Payload Encryption

When `flags.E2E` is set:

```
Inner payload = XChaCha20-Poly1305(group_key, nonce, opus_frames [+ spatial_data])
```

Nonce is 24 bytes, prepended to the inner ciphertext within the payload field.

---

## 5. Codec Negotiation

**v1:** Opus only.
- Sample rate: 48 kHz
- Channels: stereo capable
- Bitrate: 32-128 kbps variable

Framework allows future codecs via `VOICE CODECS` query and 903 numeric response. Clients and server negotiate a common codec on `VOICE JOIN`.

---

## 6. Private Channels (DMs and Group DMs)

Private conversations reuse channel infrastructure. No separate DM system.

### 6.1 Flow

```
# Alice DMs Bob on a shared server
JOIN #dm-<short-hash>
MODE #dm-<short-hash> +isEV       → invite-only, secret, E2E, voice-enabled
INVITE Bob #dm-<short-hash>

# Group DM (3+ people)
INVITE Charlie #dm-<short-hash>
```

### 6.2 Channel Modes for Private Channels

- `+i` — invite-only (existing IRC mode)
- `+s` — secret, hidden from LIST/WHOIS (existing IRC mode)
- `+E` — E2E encryption (applies to text AND voice)
- `+V` — voice-enabled (optional)

### 6.3 Text E2E Encryption

Messages in `+E` channels use an IRCv3 message tag to signal encrypted content:

```
@e2e PRIVMSG #dm-<hash> :<base64url(XChaCha20-Poly1305(shared_key, nonce, plaintext))>
```

Server routes the message but cannot read content.

### 6.4 Key Agreement for Text E2E

| Scenario | Key Derivation | Key Distribution |
|----------|---------------|-----------------|
| 2-person DM | X25519 DH from identity keys (both sides derive independently) | None needed — both sides compute from other's public key |
| Group DM (3+) | Group symmetric key (256-bit) | `VOICE KEY` / `VOICE REKEY` (same mechanism as voice E2E) |

For 2-person DMs: `shared_secret = X25519(my_ed25519_private → x25519, their_ed25519_public → x25519)`. Both sides derive the same key. No key exchange messages needed. Public keys are already in DNS.

### 6.5 Server Selection for DMs

- **v1:** Users must share a server. One joins the other's server, or they pick a mutual one.
- **Future:** Server federation could relay across linked servers.

---

## 7. Reserved for Future Versions

The following are signaled in v1 but do not require implementation:

- `VOICE MEDIA #channel screen` — screen share signaling (packet type 0x04)
- `VOICE MEDIA #channel video` — video signaling
- Stage channel mechanics (`+S` mode, hand-raise via `VOICE HAND #channel`)
- Channel linking for voice (shout across linked channels)
- WebRTC gateway compatibility (SFU can bridge to WebRTC for browser clients)
- Server federation for cross-server DM relay

---

## Appendix A: Quick Reference

### Voice Join Flow

```
Client                              Server
  |                                    |
  |  VOICE JOIN #channel               |
  |------------------------------------>|
  |                                    |
  |  :srv 900 nick #channel            |
  |    udp=host:port                   |
  |    token=<session-token>           |
  |    ssrc=<assigned-ssrc>            |
  |    mode=transport|e2e              |
  |<------------------------------------|
  |                                    |
  |  UDP: Keepalive (auth w/ token)    |
  |------------------------------------>|
  |                                    |
  |  :nick VOICESTATE #channel joined  |
  |<-----------(to all in channel)------|
  |                                    |
  |  UDP: Audio packets (encrypted)    |
  |<----------------------------------->|
```

### Packet Lifecycle (Transport Mode)

```
Speaker Client                    Server (SFU)                   Listener Client
     |                                |                                |
     | XChaCha20 encrypt (transport)  |                                |
     |------------------------------->|                                |
     |                                | Decrypt transport              |
     |                                | Read header (ssrc, seq, ts)    |
     |                                | Silence detection on payload   |
     |                                | Re-encrypt for each listener   |
     |                                |------------------------------->|
     |                                |                                | Decrypt transport
     |                                |                                | Decode Opus
     |                                |                                | Mix with other streams
```

### Packet Lifecycle (E2E Mode)

```
Speaker Client                    Server (SFU)                   Listener Client
     |                                |                                |
     | XChaCha20 encrypt (group key)  |                                |
     | XChaCha20 encrypt (transport)  |                                |
     |------------------------------->|                                |
     |                                | Decrypt transport              |
     |                                | Read header (ssrc, seq, ts)    |
     |                                | Payload is opaque (E2E flag)   |
     |                                | Forward without inspection     |
     |                                | Re-encrypt transport           |
     |                                |------------------------------->|
     |                                |                                | Decrypt transport
     |                                |                                | Decrypt E2E (group key)
     |                                |                                | Decode Opus
     |                                |                                | Mix with other streams
```
