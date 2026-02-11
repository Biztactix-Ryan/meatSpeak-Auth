namespace MeatSpeak.Identity.Tests;

public class UidTests
{
    [Fact]
    public void NewUid_GeneratesValidUid()
    {
        var uid = Uid.NewUid();
        var str = uid.ToString();

        Assert.Equal(26, str.Length);
        Assert.Equal(str, str.ToLowerInvariant());
    }

    [Fact]
    public void Parse_RoundTrips()
    {
        var uid = Uid.NewUid();
        var str = uid.ToString();
        var parsed = Uid.Parse(str);

        Assert.Equal(uid, parsed);
    }

    [Fact]
    public void Parse_CaseInsensitive()
    {
        var uid = Uid.NewUid();
        var upper = uid.ToString().ToUpperInvariant();
        var parsed = Uid.Parse(upper);

        Assert.Equal(uid, parsed);
    }

    [Fact]
    public void TryParse_ValidString_ReturnsTrue()
    {
        var uid = Uid.NewUid();
        var result = Uid.TryParse(uid.ToString(), out var parsed);

        Assert.True(result);
        Assert.Equal(uid, parsed);
    }

    [Fact]
    public void TryParse_InvalidString_ReturnsFalse()
    {
        var result = Uid.TryParse("not-a-ulid", out _);
        Assert.False(result);
    }

    [Fact]
    public void TryParse_Null_ReturnsFalse()
    {
        var result = Uid.TryParse(null, out _);
        Assert.False(result);
    }

    [Fact]
    public void Timestamp_ReturnsApproximateNow()
    {
        var before = DateTimeOffset.UtcNow;
        var uid = Uid.NewUid();
        var after = DateTimeOffset.UtcNow;

        Assert.InRange(uid.Timestamp, before.AddSeconds(-1), after.AddSeconds(1));
    }

    [Fact]
    public void Equality_SameUid_AreEqual()
    {
        var uid = Uid.NewUid();
        var copy = Uid.Parse(uid.ToString());

        Assert.Equal(uid, copy);
        Assert.True(uid == copy);
        Assert.False(uid != copy);
    }

    [Fact]
    public void Equality_DifferentUids_AreNotEqual()
    {
        var a = Uid.NewUid();
        var b = Uid.NewUid();

        Assert.NotEqual(a, b);
        Assert.True(a != b);
    }

    [Fact]
    public void ToByteArray_Returns16Bytes()
    {
        var uid = Uid.NewUid();
        var bytes = uid.ToByteArray();

        Assert.Equal(16, bytes.Length);
    }

    [Fact]
    public void CompareTo_OrdersByTimestamp()
    {
        var first = Uid.NewUid();
        Thread.Sleep(2);
        var second = Uid.NewUid();

        Assert.True(first.CompareTo(second) < 0);
    }
}
