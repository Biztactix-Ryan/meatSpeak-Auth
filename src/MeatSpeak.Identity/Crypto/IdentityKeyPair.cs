using Sodium;

namespace MeatSpeak.Identity.Crypto;

/// <summary>
/// Ed25519 keypair for MeatSpeak identity. Zeroes private key on disposal.
/// </summary>
public sealed class IdentityKeyPair : IDisposable
{
    private byte[] _privateKey;
    private bool _disposed;

    public byte[] PublicKey { get; }

    private IdentityKeyPair(byte[] publicKey, byte[] privateKey)
    {
        PublicKey = publicKey;
        _privateKey = privateKey;
    }

    public static IdentityKeyPair Generate()
    {
        var kp = PublicKeyAuth.GenerateKeyPair();
        return new IdentityKeyPair(kp.PublicKey, kp.PrivateKey);
    }

    public static IdentityKeyPair FromPrivateKey(byte[] privateKey)
    {
        var pk = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(privateKey);
        return new IdentityKeyPair(pk, (byte[])privateKey.Clone());
    }

    public byte[] Sign(byte[] message)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return PublicKeyAuth.SignDetached(message, _privateKey);
    }

    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        return PublicKeyAuth.VerifyDetached(signature, message, publicKey);
    }

    /// <summary>
    /// Returns a copy of the raw private key bytes. Caller is responsible for zeroing.
    /// </summary>
    public byte[] GetPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_privateKey.Clone();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Array.Clear(_privateKey, 0, _privateKey.Length);
    }
}
