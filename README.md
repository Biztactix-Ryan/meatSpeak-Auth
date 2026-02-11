# MeatSpeak Auth

Specification documents for the MeatSpeak authentication and identity system.

MeatSpeak is an IRC-based communication platform with modern features including decentralized identity, mutual authentication, and encrypted real-time voice. These specs define the cryptographic identity layer and voice extension protocol that underpin the platform.

## Specs

### [DNS-First Identity Layer](specs/IDENTITY-SPEC.md) (v0.2)

A decentralized identity system for open-source communities using DNS as the public directory and Ed25519 signatures for verification. No always-on central infrastructure required.

**Key concepts:**
- **ULID-based identities** -- users, servers, and identity providers all share the same cryptographic identity model
- **DNS as the public directory** -- public keys published as TXT records, with HTTPS fallback
- **Dual-source verification** -- servers publish keys in both the identity domain and their own DNS zone for independent trust anchors
- **Mutual authentication** -- Ed25519 challenge-response handshake where both client and server prove identity
- **SSO convenience layer** -- stateless identity provider issues short-lived JWTs; can be replaced without losing any identities
- **Three-layer key recovery** -- device keychain, encrypted SSO backup (Argon2id + AES-256-GCM), and BIP38-style cold backup string
- **TOFU trust model** -- SSH-style key pinning with configurable trust levels (relaxed, standard, strict)

### [Voice Extension](specs/VOICE-SPEC.md) (v0.1)

Extends IRC with real-time voice channels using an SFU (Selective Forwarding Unit) architecture. Control plane over IRC, data plane over encrypted UDP.

**Key concepts:**
- **SFU architecture** -- server forwards individual streams, clients mix locally (per-user volume, spatial audio, no server mixing cost)
- **IRC control plane** -- `VOICE` commands and `VOICESTATE` messages over the existing TCP connection
- **Encrypted UDP data plane** -- XChaCha20-Poly1305 transport encryption with 13-byte custom packet header
- **Two encryption modes** -- transport-only (`+V`) where server can do silence detection, or full E2E (`+V +E`) with a group symmetric key the server never sees
- **Spatial audio** -- optional 3D position data (12 bytes) appended to audio packets for game integration
- **Private channels** -- DMs and group DMs reuse channel infrastructure with `+isEV` modes; 2-person DMs derive shared keys from identity keys via X25519 with no key exchange needed
- **Opus codec** -- 48 kHz stereo, 32-128 kbps variable bitrate (framework supports future codec negotiation)

## Status

Both specs are in **Draft** status and under active development.

## Related Repositories

- [meatSpeak](https://github.com/Biztactix-Ryan/meatSpeak) -- Identity library implementation (.NET)
- [meatSpeak-server](https://github.com/Biztactix-Ryan/meatSpeak-server) -- Server implementation
- [meatSpeak-client](https://github.com/Biztactix-Ryan/meatSpeak-client) -- Client application

## License

See individual spec files for details.
