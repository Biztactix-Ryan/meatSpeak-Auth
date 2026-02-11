using MeatSpeak.Identity.Crypto;

namespace MeatSpeak.Identity.Tests.Crypto;

public class KeyEncryptionTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        using var kp = IdentityKeyPair.Generate();
        var privateKey = kp.GetPrivateKey();
        var password = "test-password-12345";

        var blob = KeyEncryption.Encrypt(privateKey, password);
        var decrypted = KeyEncryption.Decrypt(blob, password);

        Assert.Equal(privateKey, decrypted);
    }

    [Fact]
    public void Decrypt_WrongPassword_Throws()
    {
        using var kp = IdentityKeyPair.Generate();
        var privateKey = kp.GetPrivateKey();

        var blob = KeyEncryption.Encrypt(privateKey, "correct-password");

        Assert.ThrowsAny<Exception>(() =>
            KeyEncryption.Decrypt(blob, "wrong-password"));
    }

    [Fact]
    public void Encrypt_ProducesValidBlob()
    {
        using var kp = IdentityKeyPair.Generate();
        var privateKey = kp.GetPrivateKey();

        var blob = KeyEncryption.Encrypt(privateKey, "password");

        Assert.True(blob.Version == 0x01 || blob.Version == 0x02);
        Assert.Equal(16, blob.Salt.Length);
        Assert.True(blob.Nonce.Length is 12 or 24);
        Assert.True(blob.Ciphertext.Length > 0);
    }
}
