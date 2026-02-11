using DnsClient;
using DnsClient.Protocol;
using MeatSpeak.Identity.Dns;
using MeatSpeak.Identity.Records;

namespace MeatSpeak.Identity.Resolution;

/// <summary>
/// Resolves identity records via DNS TXT lookups using DnsClient.NET.
/// </summary>
public sealed class DnsIdentityResolver : IIdentityResolver
{
    private readonly ILookupClient _dns;

    public DnsIdentityResolver(ILookupClient? dns = null)
    {
        _dns = dns ?? new LookupClient();
    }

    public async Task<IReadOnlyList<KeyRecord>> ResolveKeysAsync(Uid uid, string domain,
        CancellationToken ct = default)
    {
        var label = $"{uid}._k.{domain}";
        return await ResolveTxtRecords(label, RecordParser.ParseKeyRecord, ct);
    }

    public async Task<IReadOnlyList<KeyRecord>> ResolveServerKeysAsync(string serverDomain,
        CancellationToken ct = default)
    {
        var label = $"_k.{serverDomain}";
        return await ResolveTxtRecords(label, RecordParser.ParseKeyRecord, ct);
    }

    public async Task<HandleRecord?> ResolveHandleAsync(string handle, string domain,
        CancellationToken ct = default)
    {
        var normalized = RecordBuilder.NormalizeHandle(handle);
        var label = $"{normalized}._h.{domain}";
        var records = await ResolveTxtRecords(label, RecordParser.ParseHandleRecord, ct);
        return records.Count > 0 ? records[0] : null;
    }

    public async Task<IdpRecord?> ResolveIdpAsync(string domain,
        CancellationToken ct = default)
    {
        var label = $"_idp.{domain}";
        var records = await ResolveTxtRecords(label, RecordParser.ParseIdpRecord, ct);
        return records.Count > 0 ? records[0] : null;
    }

    public async Task<MigrationRecord?> ResolveMigrationAsync(Uid uid, string domain,
        CancellationToken ct = default)
    {
        var label = $"{uid}._m.{domain}";
        var records = await ResolveTxtRecords(label, RecordParser.ParseMigrationRecord, ct);
        return records.Count > 0 ? records[0] : null;
    }

    private async Task<IReadOnlyList<T>> ResolveTxtRecords<T>(string label,
        Func<string, T> parser, CancellationToken ct)
    {
        IDnsQueryResponse result;
        try
        {
            result = await _dns.QueryAsync(label, QueryType.TXT, cancellationToken: ct);
        }
        catch (DnsResponseException)
        {
            return [];
        }

        var records = new List<T>();
        foreach (var answer in result.Answers.OfType<TxtRecord>())
        {
            var txt = string.Join("", answer.Text);
            try
            {
                records.Add(parser(txt));
            }
            catch (FormatException)
            {
                // Skip malformed records
            }
        }
        return records;
    }
}
