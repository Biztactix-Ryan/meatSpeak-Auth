namespace MeatSpeak.Identity.Records;

/// <summary>
/// Parsed _k TXT record: entity public key.
/// </summary>
public sealed record KeyRecord(
    int Version,
    string Algorithm,
    string Kid,
    byte[] PublicKey,
    string? Expiry = null,
    KeyFlags Flags = KeyFlags.None,
    EntityType Type = EntityType.User,
    string? ServerUid = null);

[Flags]
public enum KeyFlags
{
    None = 0,
    Primary = 1,
    Rotate = 2,
    Revoked = 4,
}
