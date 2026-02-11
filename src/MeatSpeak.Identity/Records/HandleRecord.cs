namespace MeatSpeak.Identity.Records;

/// <summary>
/// Parsed _h TXT record: handle-to-UID mapping.
/// </summary>
public sealed record HandleRecord(
    int Version,
    Uid Uid);
