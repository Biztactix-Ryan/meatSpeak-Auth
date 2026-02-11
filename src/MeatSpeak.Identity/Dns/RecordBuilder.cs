using MeatSpeak.Identity.Records;

namespace MeatSpeak.Identity.Dns;

/// <summary>
/// Builds DNS TXT record strings for publishing identity records.
/// </summary>
public static class RecordBuilder
{
    public static string BuildKeyRecord(string kid, byte[] publicKey,
        EntityType type = EntityType.User, string? expiry = null,
        KeyFlags flags = KeyFlags.None, string? serverUid = null)
    {
        var pk = Base64UrlEncode(publicKey);
        var parts = new List<string>
        {
            "v=1",
            "k=ed25519",
            $"kid={kid}",
            $"pk={pk}",
        };

        if (expiry is not null)
            parts.Add($"exp={expiry}");

        var flagList = BuildFlagString(flags);
        if (flagList is not null)
            parts.Add($"flag={flagList}");

        if (type != EntityType.User)
            parts.Add($"type={type.ToString().ToLowerInvariant()}");

        if (serverUid is not null)
            parts.Add($"uid={serverUid}");

        return string.Join(';', parts);
    }

    public static string BuildIdpRecord(string issuer, string? jwksPath = null)
    {
        var parts = new List<string>
        {
            "v=1",
            $"issuer={issuer}",
        };

        if (jwksPath is not null && jwksPath != "/.well-known/jwks.json")
            parts.Add($"jwks={jwksPath}");

        return string.Join(';', parts);
    }

    public static string BuildHandleRecord(Uid uid)
    {
        return $"v=1;uid={uid}";
    }

    public static string BuildMigrationRecord(string targetDomain,
        DateTimeOffset timestamp, byte[] signature)
    {
        var sig = Base64UrlEncode(signature);
        return $"v=1;to={targetDomain};ts={timestamp:O};sig={sig}";
    }

    public static string NormalizeHandle(string handle)
    {
        var normalized = handle.ToLowerInvariant().Replace("#", "--");
        var chars = new List<char>();
        foreach (var c in normalized)
        {
            if (char.IsLetterOrDigit(c) || c == '-')
                chars.Add(c);
        }
        return new string(chars.ToArray());
    }

    private static string? BuildFlagString(KeyFlags flags)
    {
        if (flags == KeyFlags.None) return null;

        var parts = new List<string>();
        if (flags.HasFlag(KeyFlags.Primary)) parts.Add("primary");
        if (flags.HasFlag(KeyFlags.Rotate)) parts.Add("rotate");
        if (flags.HasFlag(KeyFlags.Revoked)) parts.Add("revoked");
        return string.Join(',', parts);
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
