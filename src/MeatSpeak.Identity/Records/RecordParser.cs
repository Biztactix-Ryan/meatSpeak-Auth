using System.Globalization;

namespace MeatSpeak.Identity.Records;

/// <summary>
/// Parses DNS TXT record strings into typed record objects.
/// </summary>
public static class RecordParser
{
    public static KeyRecord ParseKeyRecord(string txt)
    {
        var fields = ParseFields(txt);

        var version = GetRequiredInt(fields, "v");
        var algorithm = GetRequired(fields, "k");
        var kid = GetRequired(fields, "kid");
        var pk = Base64UrlDecode(GetRequired(fields, "pk"));

        fields.TryGetValue("exp", out var expiry);
        var flags = ParseKeyFlags(fields.GetValueOrDefault("flag"));
        var type = ParseEntityType(fields.GetValueOrDefault("type"));
        fields.TryGetValue("uid", out var serverUid);

        return new KeyRecord(version, algorithm, kid, pk, expiry, flags, type, serverUid);
    }

    public static IdpRecord ParseIdpRecord(string txt)
    {
        var fields = ParseFields(txt);

        var version = GetRequiredInt(fields, "v");
        var issuer = GetRequired(fields, "issuer");
        var jwks = fields.GetValueOrDefault("jwks", "/.well-known/jwks.json");

        return new IdpRecord(version, issuer, jwks);
    }

    public static HandleRecord ParseHandleRecord(string txt)
    {
        var fields = ParseFields(txt);

        var version = GetRequiredInt(fields, "v");
        var uid = Uid.Parse(GetRequired(fields, "uid"));

        return new HandleRecord(version, uid);
    }

    public static MigrationRecord ParseMigrationRecord(string txt)
    {
        var fields = ParseFields(txt);

        var version = GetRequiredInt(fields, "v");
        var to = GetRequired(fields, "to");
        var ts = DateTimeOffset.Parse(GetRequired(fields, "ts"), CultureInfo.InvariantCulture);
        var sig = Base64UrlDecode(GetRequired(fields, "sig"));

        return new MigrationRecord(version, to, ts, sig);
    }

    internal static Dictionary<string, string> ParseFields(string txt)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in txt.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex < 0) continue;
            var key = pair[..eqIndex].Trim();
            var value = pair[(eqIndex + 1)..].Trim();
            fields[key] = value;
        }
        return fields;
    }

    private static string GetRequired(Dictionary<string, string> fields, string key)
    {
        if (!fields.TryGetValue(key, out var value) || string.IsNullOrEmpty(value))
            throw new FormatException($"Missing required field '{key}' in TXT record.");
        return value;
    }

    private static int GetRequiredInt(Dictionary<string, string> fields, string key)
    {
        var value = GetRequired(fields, key);
        if (!int.TryParse(value, out var result))
            throw new FormatException($"Field '{key}' must be an integer, got '{value}'.");
        return result;
    }

    private static KeyFlags ParseKeyFlags(string? flagStr)
    {
        if (string.IsNullOrEmpty(flagStr)) return KeyFlags.None;

        var flags = KeyFlags.None;
        foreach (var part in flagStr.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            flags |= part.ToLowerInvariant() switch
            {
                "primary" => KeyFlags.Primary,
                "rotate" => KeyFlags.Rotate,
                "revoked" => KeyFlags.Revoked,
                _ => KeyFlags.None,
            };
        }
        return flags;
    }

    private static EntityType ParseEntityType(string? typeStr)
    {
        if (string.IsNullOrEmpty(typeStr)) return EntityType.User;
        return typeStr.ToLowerInvariant() switch
        {
            "user" => EntityType.User,
            "server" => EntityType.Server,
            "idp" => EntityType.Idp,
            _ => EntityType.User,
        };
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var s = base64Url.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}
