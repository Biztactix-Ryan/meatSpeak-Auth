namespace MeatSpeak.Identity.Records;

/// <summary>
/// Parsed _idp TXT record: identity provider discovery.
/// </summary>
public sealed record IdpRecord(
    int Version,
    string Issuer,
    string JwksPath = "/.well-known/jwks.json");
