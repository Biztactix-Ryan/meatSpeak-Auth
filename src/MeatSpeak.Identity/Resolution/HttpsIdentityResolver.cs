using System.Net.Http.Json;
using System.Text.Json;
using MeatSpeak.Identity.Records;

namespace MeatSpeak.Identity.Resolution;

/// <summary>
/// HTTPS fallback resolver. Queries /k/{uid} and /h/{handle} endpoints.
/// </summary>
public sealed class HttpsIdentityResolver : IIdentityResolver
{
    private readonly HttpClient _http;

    public HttpsIdentityResolver(HttpClient? http = null)
    {
        _http = http ?? new HttpClient();
    }

    public async Task<IReadOnlyList<KeyRecord>> ResolveKeysAsync(Uid uid, string domain,
        CancellationToken ct = default)
    {
        var issuer = await GetIssuerAsync(domain, ct);
        if (issuer is null) return [];

        try
        {
            var url = $"{issuer}/k/{uid}";
            var entries = await _http.GetFromJsonAsync<JsonElement[]>(url, ct);
            if (entries is null) return [];

            return entries
                .Select(e => RecordParser.ParseKeyRecord(e.GetString()!))
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    public Task<IReadOnlyList<KeyRecord>> ResolveServerKeysAsync(string serverDomain,
        CancellationToken ct = default)
    {
        // HTTPS fallback for server self-published keys is not standard;
        // fall back to the identity domain HTTPS endpoint if available.
        return Task.FromResult<IReadOnlyList<KeyRecord>>([]);
    }

    public async Task<HandleRecord?> ResolveHandleAsync(string handle, string domain,
        CancellationToken ct = default)
    {
        var issuer = await GetIssuerAsync(domain, ct);
        if (issuer is null) return null;

        try
        {
            var normalized = Dns.RecordBuilder.NormalizeHandle(handle);
            var url = $"{issuer}/h/{normalized}";
            var json = await _http.GetFromJsonAsync<JsonElement>(url, ct);
            if (json.TryGetProperty("uid", out var uidProp))
            {
                var uid = Uid.Parse(uidProp.GetString()!);
                return new HandleRecord(1, uid);
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    public async Task<IdpRecord?> ResolveIdpAsync(string domain,
        CancellationToken ct = default)
    {
        // IDP discovery via HTTPS is the JWKS endpoint itself
        try
        {
            var url = $"https://{domain}/.well-known/jwks.json";
            var response = await _http.GetAsync(url, ct);
            if (response.IsSuccessStatusCode)
                return new IdpRecord(1, $"https://{domain}");
        }
        catch { }
        return null;
    }

    public Task<MigrationRecord?> ResolveMigrationAsync(Uid uid, string domain,
        CancellationToken ct = default)
    {
        // Migration records are DNS-only in v1
        return Task.FromResult<MigrationRecord?>(null);
    }

    private async Task<string?> GetIssuerAsync(string domain, CancellationToken ct)
    {
        // Try to discover issuer, or default to https://domain
        var idp = await ResolveIdpAsync(domain, ct);
        return idp?.Issuer ?? $"https://{domain}";
    }
}
