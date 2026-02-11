namespace MeatSpeak.Identity.Auth;

/// <summary>
/// Server's challenge message in mutual authentication handshake.
/// </summary>
public sealed record ServerHello(
    Uid ServerUid,
    string Kid,
    byte[] Nonce,
    DateTimeOffset Timestamp,
    byte[] Signature);
