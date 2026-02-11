using System.Security.Cryptography;
using Sodium;

namespace MeatSpeak.Identity.Crypto;

/// <summary>
/// Argon2id + AES-256-GCM encrypted backup blob for SSO storage.
/// Falls back to XChaCha20-Poly1305 when AES-NI is unavailable (version byte differentiates).
/// </summary>
public static class KeyEncryption
{
    private const int SaltLength = 16;
    private const int NonceLength = 12; // AES-GCM nonce
    private const int XNonceLength = 24; // XChaCha20-Poly1305 nonce
    private const int KeyLength = 32;
    private const int TagLength = 16;

    // Version bytes
    private const byte VersionAesGcm = 0x01;
    private const byte VersionXChaCha = 0x02;

    // Argon2id default params
    public const int DefaultMemoryBytes = 268435456; // 256 MB
    public const long DefaultOpsLimit = 3;

    public static EncryptedBlob Encrypt(byte[] privateKey, string password)
    {
        var salt = SodiumCore.GetRandomBytes(SaltLength);
        var derivedKey = DeriveKey(password, salt, DefaultOpsLimit, DefaultMemoryBytes);

        try
        {
            if (AesGcm.IsSupported)
            {
                var nonce = SodiumCore.GetRandomBytes(NonceLength);
                var ciphertext = new byte[privateKey.Length];
                var tag = new byte[TagLength];
                using var aes = new AesGcm(derivedKey, TagLength);
                aes.Encrypt(nonce, privateKey, ciphertext, tag);

                var combined = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, combined, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, combined, ciphertext.Length, tag.Length);

                return new EncryptedBlob(VersionAesGcm, salt, nonce,
                    DefaultOpsLimit, DefaultMemoryBytes, combined);
            }
            else
            {
                var nonce = SodiumCore.GetRandomBytes(XNonceLength);
                var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(
                    privateKey, nonce, derivedKey);

                return new EncryptedBlob(VersionXChaCha, salt, nonce,
                    DefaultOpsLimit, DefaultMemoryBytes, ciphertext);
            }
        }
        finally
        {
            Array.Clear(derivedKey, 0, derivedKey.Length);
        }
    }

    public static byte[] Decrypt(EncryptedBlob blob, string password)
    {
        var derivedKey = DeriveKey(password, blob.Salt, blob.OpsLimit, blob.MemoryBytes);

        try
        {
            if (blob.Version == VersionAesGcm)
            {
                var ciphertext = blob.Ciphertext[..^TagLength];
                var tag = blob.Ciphertext[^TagLength..];
                var plaintext = new byte[ciphertext.Length];
                using var aes = new AesGcm(derivedKey, TagLength);
                aes.Decrypt(blob.Nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            else if (blob.Version == VersionXChaCha)
            {
                return SecretAeadXChaCha20Poly1305.Decrypt(
                    blob.Ciphertext, blob.Nonce, derivedKey);
            }
            else
            {
                throw new NotSupportedException($"Unknown encryption version: {blob.Version}");
            }
        }
        finally
        {
            Array.Clear(derivedKey, 0, derivedKey.Length);
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt, long opsLimit, int memoryBytes)
    {
        return PasswordHash.ArgonHashBinary(
            System.Text.Encoding.UTF8.GetBytes(password),
            salt,
            opsLimit,
            memoryBytes,
            KeyLength,
            PasswordHash.ArgonAlgorithm.Argon_2ID13);
    }
}

public sealed record EncryptedBlob(
    byte Version,
    byte[] Salt,
    byte[] Nonce,
    long OpsLimit,
    int MemoryBytes,
    byte[] Ciphertext);
