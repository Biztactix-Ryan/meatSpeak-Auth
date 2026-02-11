using MeatSpeak.Identity.Crypto;

namespace MeatSpeak.Identity.Tests.Crypto;

public class ColdBackupTests
{
    [Fact]
    public void EncodeDecode_RoundTrip()
    {
        using var kp = IdentityKeyPair.Generate();
        var privateKey = kp.GetPrivateKey();
        var passphrase = "my-strong-passphrase-123";

        var backup = ColdBackup.Encode(privateKey, passphrase);
        var decoded = ColdBackup.Decode(backup, passphrase);

        Assert.Equal(privateKey, decoded);
    }

    [Fact]
    public void Encode_StartsWithPrefix()
    {
        using var kp = IdentityKeyPair.Generate();
        var backup = ColdBackup.Encode(kp.GetPrivateKey(), "passphrase");

        Assert.StartsWith("idk1-", backup);
    }

    [Fact]
    public void Decode_WrongPassphrase_Throws()
    {
        using var kp = IdentityKeyPair.Generate();
        var backup = ColdBackup.Encode(kp.GetPrivateKey(), "correct");

        Assert.ThrowsAny<Exception>(() =>
            ColdBackup.Decode(backup, "wrong"));
    }

    [Fact]
    public void Decode_CorruptedString_Throws()
    {
        using var kp = IdentityKeyPair.Generate();
        var backup = ColdBackup.Encode(kp.GetPrivateKey(), "pass");
        var corrupted = backup[..^3] + "XXX";

        Assert.ThrowsAny<Exception>(() =>
            ColdBackup.Decode(corrupted, "pass"));
    }

    [Fact]
    public void Decode_InvalidPrefix_Throws()
    {
        Assert.Throws<FormatException>(() =>
            ColdBackup.Decode("bad-prefix-string", "pass"));
    }

    [Fact]
    public void EncodeDecode_RestoredKeyCanSign()
    {
        using var original = IdentityKeyPair.Generate();
        var passphrase = "recovery-test";

        var backup = ColdBackup.Encode(original.GetPrivateKey(), passphrase);
        var recoveredKey = ColdBackup.Decode(backup, passphrase);
        using var restored = IdentityKeyPair.FromPrivateKey(recoveredKey);

        Assert.Equal(original.PublicKey, restored.PublicKey);

        var message = "verify-after-recovery"u8.ToArray();
        var sig = restored.Sign(message);
        Assert.True(IdentityKeyPair.Verify(message, sig, original.PublicKey));
    }
}
