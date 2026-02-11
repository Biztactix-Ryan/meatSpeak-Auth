using MeatSpeak.Identity.Crypto;
using MeatSpeak.Identity.Records;
using MeatSpeak.Identity.Resolution;

namespace MeatSpeak.Identity.Verification;

/// <summary>
/// Verifies a server's identity against two independent DNS sources
/// (identity domain + server's own domain).
/// </summary>
public sealed class DualSourceVerifier
{
    private readonly IIdentityResolver _resolver;

    public DualSourceVerifier(IIdentityResolver resolver)
    {
        _resolver = resolver;
    }

    public async Task<VerifyResult> VerifyServerAsync(
        Uid serverUid,
        string serverDomain,
        string identityDomain,
        string kid,
        byte[] challenge,
        byte[] signature,
        CancellationToken ct = default)
    {
        // Source 1: identity domain
        var idKeys = await _resolver.ResolveKeysAsync(serverUid, identityDomain, ct);
        var idKey = FindKey(idKeys, kid);

        // Source 2: server's own domain
        var selfKeys = await _resolver.ResolveServerKeysAsync(serverDomain, ct);
        var selfKey = FindKey(selfKeys, kid);

        // Dual-source comparison
        if (idKey is not null && selfKey is not null)
        {
            if (!idKey.PublicKey.AsSpan().SequenceEqual(selfKey.PublicKey))
                return VerifyResult.KeyMismatch;
        }

        // Pick whichever key we have
        var key = idKey ?? selfKey;
        if (key is null)
            return VerifyResult.NoKeyFound;

        // Verify signature
        if (!IdentityKeyPair.Verify(challenge, signature, key.PublicKey))
            return VerifyResult.SignatureFailed;

        // Both sources agree = Verified, single source = Partial
        return (idKey is not null && selfKey is not null)
            ? VerifyResult.Verified
            : VerifyResult.Partial;
    }

    private static KeyRecord? FindKey(IReadOnlyList<KeyRecord> keys, string kid)
    {
        return keys.FirstOrDefault(k =>
            k.Kid == kid && !k.Flags.HasFlag(KeyFlags.Revoked));
    }
}
