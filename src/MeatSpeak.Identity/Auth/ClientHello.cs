namespace MeatSpeak.Identity.Auth;

/// <summary>
/// Client's response message in mutual authentication handshake.
/// </summary>
public sealed record ClientHello(
    Uid UserUid,
    string Kid,
    byte[] Nonce,
    DateTimeOffset Timestamp,
    byte[] Signature);
