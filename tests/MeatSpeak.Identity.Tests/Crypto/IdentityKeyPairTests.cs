using MeatSpeak.Identity.Crypto;

namespace MeatSpeak.Identity.Tests.Crypto;

public class IdentityKeyPairTests
{
    [Fact]
    public void Generate_CreatesValidKeyPair()
    {
        using var kp = IdentityKeyPair.Generate();

        Assert.NotNull(kp.PublicKey);
        Assert.Equal(32, kp.PublicKey.Length);
    }

    [Fact]
    public void Sign_Verify_RoundTrip()
    {
        using var kp = IdentityKeyPair.Generate();
        var message = "hello world"u8.ToArray();

        var signature = kp.Sign(message);

        Assert.Equal(64, signature.Length);
        Assert.True(IdentityKeyPair.Verify(message, signature, kp.PublicKey));
    }

    [Fact]
    public void Verify_WrongMessage_ReturnsFalse()
    {
        using var kp = IdentityKeyPair.Generate();
        var message = "hello"u8.ToArray();
        var wrong = "world"u8.ToArray();

        var signature = kp.Sign(message);

        Assert.False(IdentityKeyPair.Verify(wrong, signature, kp.PublicKey));
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        using var kp1 = IdentityKeyPair.Generate();
        using var kp2 = IdentityKeyPair.Generate();
        var message = "test"u8.ToArray();

        var signature = kp1.Sign(message);

        Assert.False(IdentityKeyPair.Verify(message, signature, kp2.PublicKey));
    }

    [Fact]
    public void FromPrivateKey_RestoresKeyPair()
    {
        using var original = IdentityKeyPair.Generate();
        var privateKey = original.GetPrivateKey();

        using var restored = IdentityKeyPair.FromPrivateKey(privateKey);

        Assert.Equal(original.PublicKey, restored.PublicKey);

        // Verify signature compatibility
        var message = "round-trip"u8.ToArray();
        var sig = original.Sign(message);
        Assert.True(IdentityKeyPair.Verify(message, sig, restored.PublicKey));
    }

    [Fact]
    public void Dispose_ZeroesPrivateKey()
    {
        var kp = IdentityKeyPair.Generate();
        var privateKey = kp.GetPrivateKey();
        Assert.Contains(privateKey, b => b != 0); // key should have non-zero bytes

        kp.Dispose();

        Assert.Throws<ObjectDisposedException>(() => kp.Sign("test"u8.ToArray()));
        Assert.Throws<ObjectDisposedException>(() => kp.GetPrivateKey());
    }

    [Fact]
    public void GetPrivateKey_ReturnsCopy()
    {
        using var kp = IdentityKeyPair.Generate();
        var pk1 = kp.GetPrivateKey();
        var pk2 = kp.GetPrivateKey();

        Assert.Equal(pk1, pk2);
        Assert.False(ReferenceEquals(pk1, pk2));
    }
}
