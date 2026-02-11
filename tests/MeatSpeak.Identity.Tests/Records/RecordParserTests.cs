using MeatSpeak.Identity.Dns;
using MeatSpeak.Identity.Records;

namespace MeatSpeak.Identity.Tests.Records;

public class RecordParserTests
{
    [Fact]
    public void ParseKeyRecord_AllFields()
    {
        var pk = new byte[] { 1, 2, 3, 4, 5 };
        var pkB64 = Convert.ToBase64String(pk).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var txt = $"v=1;k=ed25519;kid=2026-02;pk={pkB64};exp=2027-01-01;flag=primary,rotate;type=server;uid=01j5srv7pm9qwr4txyz6bn8vhe";

        var record = RecordParser.ParseKeyRecord(txt);

        Assert.Equal(1, record.Version);
        Assert.Equal("ed25519", record.Algorithm);
        Assert.Equal("2026-02", record.Kid);
        Assert.Equal(pk, record.PublicKey);
        Assert.Equal("2027-01-01", record.Expiry);
        Assert.Equal(KeyFlags.Primary | KeyFlags.Rotate, record.Flags);
        Assert.Equal(EntityType.Server, record.Type);
        Assert.Equal("01j5srv7pm9qwr4txyz6bn8vhe", record.ServerUid);
    }

    [Fact]
    public void ParseKeyRecord_MinimalFields()
    {
        var pk = new byte[] { 10, 20, 30 };
        var pkB64 = Convert.ToBase64String(pk).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var txt = $"v=1;k=ed25519;kid=test;pk={pkB64}";

        var record = RecordParser.ParseKeyRecord(txt);

        Assert.Equal(1, record.Version);
        Assert.Equal("ed25519", record.Algorithm);
        Assert.Equal("test", record.Kid);
        Assert.Equal(pk, record.PublicKey);
        Assert.Null(record.Expiry);
        Assert.Equal(KeyFlags.None, record.Flags);
        Assert.Equal(EntityType.User, record.Type);
        Assert.Null(record.ServerUid);
    }

    [Fact]
    public void ParseKeyRecord_MissingRequiredField_Throws()
    {
        Assert.Throws<FormatException>(() =>
            RecordParser.ParseKeyRecord("v=1;k=ed25519;kid=test"));
    }

    [Fact]
    public void ParseIdpRecord_AllFields()
    {
        var txt = "v=1;issuer=https://id.example.org;jwks=/custom/jwks.json";

        var record = RecordParser.ParseIdpRecord(txt);

        Assert.Equal(1, record.Version);
        Assert.Equal("https://id.example.org", record.Issuer);
        Assert.Equal("/custom/jwks.json", record.JwksPath);
    }

    [Fact]
    public void ParseIdpRecord_DefaultJwks()
    {
        var txt = "v=1;issuer=https://id.example.org";

        var record = RecordParser.ParseIdpRecord(txt);

        Assert.Equal("/.well-known/jwks.json", record.JwksPath);
    }

    [Fact]
    public void ParseHandleRecord_ValidRecord()
    {
        var uid = Uid.NewUid();
        var txt = $"v=1;uid={uid}";

        var record = RecordParser.ParseHandleRecord(txt);

        Assert.Equal(1, record.Version);
        Assert.Equal(uid, record.Uid);
    }

    [Fact]
    public void ParseMigrationRecord_ValidRecord()
    {
        var sig = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var sigB64 = Convert.ToBase64String(sig).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var ts = "2026-03-01T00:00:00Z";
        var txt = $"v=1;to=id.newdomain.org;ts={ts};sig={sigB64}";

        var record = RecordParser.ParseMigrationRecord(txt);

        Assert.Equal(1, record.Version);
        Assert.Equal("id.newdomain.org", record.TargetDomain);
        Assert.Equal(new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero), record.Timestamp);
        Assert.Equal(sig, record.Signature);
    }

    [Fact]
    public void KeyRecord_BuildAndParse_RoundTrip()
    {
        var pk = new byte[32];
        Random.Shared.NextBytes(pk);
        var kid = "2026-02";

        var txt = RecordBuilder.BuildKeyRecord(kid, pk,
            type: EntityType.Server, flags: KeyFlags.Primary, expiry: "2027-01-01");
        var parsed = RecordParser.ParseKeyRecord(txt);

        Assert.Equal("ed25519", parsed.Algorithm);
        Assert.Equal(kid, parsed.Kid);
        Assert.Equal(pk, parsed.PublicKey);
        Assert.Equal(EntityType.Server, parsed.Type);
        Assert.Equal(KeyFlags.Primary, parsed.Flags);
        Assert.Equal("2027-01-01", parsed.Expiry);
    }

    [Fact]
    public void IdpRecord_BuildAndParse_RoundTrip()
    {
        var txt = RecordBuilder.BuildIdpRecord("https://id.example.org");
        var parsed = RecordParser.ParseIdpRecord(txt);

        Assert.Equal("https://id.example.org", parsed.Issuer);
        Assert.Equal("/.well-known/jwks.json", parsed.JwksPath);
    }

    [Fact]
    public void HandleRecord_BuildAndParse_RoundTrip()
    {
        var uid = Uid.NewUid();
        var txt = RecordBuilder.BuildHandleRecord(uid);
        var parsed = RecordParser.ParseHandleRecord(txt);

        Assert.Equal(uid, parsed.Uid);
    }

    [Fact]
    public void NormalizeHandle_ConvertsCorrectly()
    {
        Assert.Equal("alice--1234", RecordBuilder.NormalizeHandle("Alice#1234"));
        Assert.Equal("bob", RecordBuilder.NormalizeHandle("BOB"));
        Assert.Equal("test-user", RecordBuilder.NormalizeHandle("Test-User"));
    }
}
