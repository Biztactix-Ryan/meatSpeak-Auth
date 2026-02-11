using MeatSpeak.Identity.Records;

namespace MeatSpeak.Identity.Resolution;

/// <summary>
/// Tries DNS first, falls back to HTTPS.
/// </summary>
public sealed class FallbackResolver : IIdentityResolver
{
    private readonly IIdentityResolver _primary;
    private readonly IIdentityResolver _fallback;

    public FallbackResolver(IIdentityResolver primary, IIdentityResolver fallback)
    {
        _primary = primary;
        _fallback = fallback;
    }

    public FallbackResolver()
        : this(new DnsIdentityResolver(), new HttpsIdentityResolver()) { }

    public async Task<IReadOnlyList<KeyRecord>> ResolveKeysAsync(Uid uid, string domain,
        CancellationToken ct = default)
    {
        var result = await _primary.ResolveKeysAsync(uid, domain, ct);
        if (result.Count > 0) return result;
        return await _fallback.ResolveKeysAsync(uid, domain, ct);
    }

    public async Task<IReadOnlyList<KeyRecord>> ResolveServerKeysAsync(string serverDomain,
        CancellationToken ct = default)
    {
        var result = await _primary.ResolveServerKeysAsync(serverDomain, ct);
        if (result.Count > 0) return result;
        return await _fallback.ResolveServerKeysAsync(serverDomain, ct);
    }

    public async Task<HandleRecord?> ResolveHandleAsync(string handle, string domain,
        CancellationToken ct = default)
    {
        var result = await _primary.ResolveHandleAsync(handle, domain, ct);
        if (result is not null) return result;
        return await _fallback.ResolveHandleAsync(handle, domain, ct);
    }

    public async Task<IdpRecord?> ResolveIdpAsync(string domain,
        CancellationToken ct = default)
    {
        var result = await _primary.ResolveIdpAsync(domain, ct);
        if (result is not null) return result;
        return await _fallback.ResolveIdpAsync(domain, ct);
    }

    public async Task<MigrationRecord?> ResolveMigrationAsync(Uid uid, string domain,
        CancellationToken ct = default)
    {
        var result = await _primary.ResolveMigrationAsync(uid, domain, ct);
        if (result is not null) return result;
        return await _fallback.ResolveMigrationAsync(uid, domain, ct);
    }
}
