using System.Security.Cryptography;
using SimpleBase;
using Sodium;

namespace MeatSpeak.Identity.Crypto;

/// <summary>
/// BIP38-style cold backup string (idk1- prefix, Base58Check encoded).
/// Format: prefix | version(1) | argon2_params(3) | salt(16) | encrypted_key+tag(48)
/// </summary>
public static class ColdBackup
{
    private const string Prefix = "idk1-";
    private const byte CurrentVersion = 0x01;
    private const int SaltLen = 16;
    private const int KeyLen = 32;
    private const int ChecksumLen = 4;
    private const int NonceLen = 24; // XChaCha20-Poly1305

    // Argon2id params packed into 3 bytes:
    // byte 0: memory exponent (2^n KB), byte 1: iterations, byte 2: parallelism
    private const byte DefaultMemoryExp = 18; // 2^18 = 256 MB
    private const byte DefaultIterations = 3;
    private const byte DefaultParallelism = 4;

    public static string Encode(byte[] privateKey, string passphrase)
    {
        var salt = SodiumCore.GetRandomBytes(SaltLen);
        int memoryBytes = 1 << (DefaultMemoryExp + 10); // 2^exp KB -> bytes

        var derivedKey = PasswordHash.ArgonHashBinary(
            System.Text.Encoding.UTF8.GetBytes(passphrase),
            salt,
            (long)DefaultIterations,
            memoryBytes,
            KeyLen,
            PasswordHash.ArgonAlgorithm.Argon_2ID13);

        try
        {
            var nonce = new byte[NonceLen]; // deterministic nonce from salt hash
            var saltHash = GenericHash.Hash(salt, null, NonceLen);
            Buffer.BlockCopy(saltHash, 0, nonce, 0, NonceLen);

            var encrypted = SecretAeadXChaCha20Poly1305.Encrypt(
                privateKey, nonce, derivedKey);

            // Build payload: version(1) + params(3) + salt(16) + ciphertext(48)
            var payloadLen = 1 + 3 + SaltLen + encrypted.Length;
            var payload = new byte[payloadLen];
            payload[0] = CurrentVersion;
            payload[1] = DefaultMemoryExp;
            payload[2] = DefaultIterations;
            payload[3] = DefaultParallelism;
            Buffer.BlockCopy(salt, 0, payload, 4, SaltLen);
            Buffer.BlockCopy(encrypted, 0, payload, 4 + SaltLen, encrypted.Length);

            // Checksum (first 4 bytes of SHA-256 double-hash)
            var checksum = ComputeChecksum(payload);
            var withChecksum = new byte[payloadLen + ChecksumLen];
            Buffer.BlockCopy(payload, 0, withChecksum, 0, payloadLen);
            Buffer.BlockCopy(checksum, 0, withChecksum, payloadLen, ChecksumLen);

            return Prefix + Base58.Bitcoin.Encode(withChecksum);
        }
        finally
        {
            Array.Clear(derivedKey, 0, derivedKey.Length);
        }
    }

    public static byte[] Decode(string backupString, string passphrase)
    {
        if (!backupString.StartsWith(Prefix))
            throw new FormatException("Invalid backup string prefix.");

        var encoded = backupString[Prefix.Length..];
        var withChecksum = Base58.Bitcoin.Decode(encoded).ToArray();

        if (withChecksum.Length < ChecksumLen + 1 + 3 + SaltLen)
            throw new FormatException("Backup string too short.");

        // Verify checksum
        var payloadLen = withChecksum.Length - ChecksumLen;
        var payload = withChecksum[..payloadLen];
        var storedChecksum = withChecksum[payloadLen..];
        var computedChecksum = ComputeChecksum(payload);
        if (!storedChecksum.AsSpan().SequenceEqual(computedChecksum.AsSpan()))
            throw new FormatException("Checksum mismatch — corrupted backup string.");

        // Parse payload
        var version = payload[0];
        if (version != CurrentVersion)
            throw new NotSupportedException($"Unsupported backup version: {version}");

        var memoryExp = payload[1];
        var iterations = payload[2];
        // parallelism = payload[3]; // not used by Sodium.Core Argon2 API directly

        var salt = payload[4..(4 + SaltLen)];
        var encrypted = payload[(4 + SaltLen)..];

        int memoryBytes = 1 << (memoryExp + 10); // 2^exp KB -> bytes

        var derivedKey = PasswordHash.ArgonHashBinary(
            System.Text.Encoding.UTF8.GetBytes(passphrase),
            salt,
            (long)iterations,
            memoryBytes,
            KeyLen,
            PasswordHash.ArgonAlgorithm.Argon_2ID13);

        try
        {
            var nonce = new byte[NonceLen];
            var saltHash = GenericHash.Hash(salt, null, NonceLen);
            Buffer.BlockCopy(saltHash, 0, nonce, 0, NonceLen);

            return SecretAeadXChaCha20Poly1305.Decrypt(
                encrypted, nonce, derivedKey);
        }
        finally
        {
            Array.Clear(derivedKey, 0, derivedKey.Length);
        }
    }

    private static byte[] ComputeChecksum(byte[] data)
    {
        var hash1 = SHA256.HashData(data);
        var hash2 = SHA256.HashData(hash1);
        return hash2[..ChecksumLen];
    }
}
