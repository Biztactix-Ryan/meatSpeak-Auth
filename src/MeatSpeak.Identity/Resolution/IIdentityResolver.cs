using MeatSpeak.Identity.Records;

namespace MeatSpeak.Identity.Resolution;

/// <summary>
/// Resolves identity records from DNS or HTTPS sources.
/// </summary>
public interface IIdentityResolver
{
    Task<IReadOnlyList<KeyRecord>> ResolveKeysAsync(Uid uid, string domain,
        CancellationToken ct = default);

    Task<IReadOnlyList<KeyRecord>> ResolveServerKeysAsync(string serverDomain,
        CancellationToken ct = default);

    Task<HandleRecord?> ResolveHandleAsync(string handle, string domain,
        CancellationToken ct = default);

    Task<IdpRecord?> ResolveIdpAsync(string domain,
        CancellationToken ct = default);

    Task<MigrationRecord?> ResolveMigrationAsync(Uid uid, string domain,
        CancellationToken ct = default);
}
