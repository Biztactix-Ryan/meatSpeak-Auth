using Sodium;

namespace MeatSpeak.Identity.Trust;

/// <summary>
/// TOFU verification logic: pin on first use, warn on key change.
/// </summary>
public sealed class TofuVerifier
{
    private readonly ITofuStore _store;

    public TofuVerifier(ITofuStore store)
    {
        _store = store;
    }

    public async Task<TofuResult> VerifyAsync(string entityId, byte[] publicKey,
        TofuSources sources, CancellationToken ct = default)
    {
        var fingerprint = ComputeFingerprint(publicKey);
        var existingPin = await _store.GetPinAsync(entityId, ct);

        if (existingPin is null)
        {
            // First use — pin it
            var pin = new TofuPin(entityId, fingerprint, DateTimeOffset.UtcNow, sources);
            await _store.SetPinAsync(pin, ct);
            return TofuResult.TrustedFirstUse;
        }

        if (existingPin.KeyFingerprint == fingerprint)
            return TofuResult.TrustedPinMatch;

        return TofuResult.KeyChanged;
    }

    public static string ComputeFingerprint(byte[] publicKey)
    {
        var hash = GenericHash.Hash(publicKey, null, 32);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

public enum TofuResult
{
    TrustedFirstUse,
    TrustedPinMatch,
    KeyChanged,
}
