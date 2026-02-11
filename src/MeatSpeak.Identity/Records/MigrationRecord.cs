namespace MeatSpeak.Identity.Records;

/// <summary>
/// Parsed _m TXT record: domain migration pointer.
/// </summary>
public sealed record MigrationRecord(
    int Version,
    string TargetDomain,
    DateTimeOffset Timestamp,
    byte[] Signature);
