using System.Text;
using MeatSpeak.Identity.Crypto;
using Sodium;

namespace MeatSpeak.Identity.Auth;

/// <summary>
/// Creates and verifies mutual authentication handshake messages.
/// </summary>
public static class MutualAuth
{
    private static readonly TimeSpan MaxTimestampSkew = TimeSpan.FromMinutes(5);
    private const int NonceLength = 16;

    /// <summary>
    /// Create a ServerHello message: server signs (nonce_s | timestamp).
    /// </summary>
    public static ServerHello CreateServerHello(Uid serverUid, string kid,
        IdentityKeyPair serverKey)
    {
        var nonce = SodiumCore.GetRandomBytes(NonceLength);
        var timestamp = DateTimeOffset.UtcNow;
        var payload = BuildServerPayload(nonce, timestamp);
        var signature = serverKey.Sign(payload);
        return new ServerHello(serverUid, kid, nonce, timestamp, signature);
    }

    /// <summary>
    /// Verify a ServerHello message signature.
    /// </summary>
    public static bool VerifyServerHello(ServerHello hello, byte[] serverPublicKey)
    {
        if (!IsTimestampValid(hello.Timestamp))
            return false;

        var payload = BuildServerPayload(hello.Nonce, hello.Timestamp);
        return IdentityKeyPair.Verify(payload, hello.Signature, serverPublicKey);
    }

    /// <summary>
    /// Create a ClientHello message: client signs (nonce_s | nonce_c | server_uid | timestamp).
    /// </summary>
    public static ClientHello CreateClientHello(Uid userUid, string kid,
        IdentityKeyPair userKey, byte[] serverNonce, Uid serverUid)
    {
        var nonce = SodiumCore.GetRandomBytes(NonceLength);
        var timestamp = DateTimeOffset.UtcNow;
        var payload = BuildClientPayload(serverNonce, nonce, serverUid, timestamp);
        var signature = userKey.Sign(payload);
        return new ClientHello(userUid, kid, nonce, timestamp, signature);
    }

    /// <summary>
    /// Verify a ClientHello message signature.
    /// </summary>
    public static bool VerifyClientHello(ClientHello hello, byte[] userPublicKey,
        byte[] serverNonce, Uid serverUid)
    {
        if (!IsTimestampValid(hello.Timestamp))
            return false;

        var payload = BuildClientPayload(serverNonce, hello.Nonce, serverUid, hello.Timestamp);
        return IdentityKeyPair.Verify(payload, hello.Signature, userPublicKey);
    }

    private static byte[] BuildServerPayload(byte[] nonce, DateTimeOffset timestamp)
    {
        var tsBytes = Encoding.UTF8.GetBytes(timestamp.ToUnixTimeSeconds().ToString());
        var payload = new byte[nonce.Length + tsBytes.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(tsBytes, 0, payload, nonce.Length, tsBytes.Length);
        return payload;
    }

    private static byte[] BuildClientPayload(byte[] serverNonce, byte[] clientNonce,
        Uid serverUid, DateTimeOffset timestamp)
    {
        var uidBytes = Encoding.UTF8.GetBytes(serverUid.ToString());
        var tsBytes = Encoding.UTF8.GetBytes(timestamp.ToUnixTimeSeconds().ToString());
        var total = serverNonce.Length + clientNonce.Length + uidBytes.Length + tsBytes.Length;
        var payload = new byte[total];
        var offset = 0;

        Buffer.BlockCopy(serverNonce, 0, payload, offset, serverNonce.Length);
        offset += serverNonce.Length;

        Buffer.BlockCopy(clientNonce, 0, payload, offset, clientNonce.Length);
        offset += clientNonce.Length;

        Buffer.BlockCopy(uidBytes, 0, payload, offset, uidBytes.Length);
        offset += uidBytes.Length;

        Buffer.BlockCopy(tsBytes, 0, payload, offset, tsBytes.Length);
        return payload;
    }

    private static bool IsTimestampValid(DateTimeOffset timestamp)
    {
        var diff = DateTimeOffset.UtcNow - timestamp;
        return diff.Duration() <= MaxTimestampSkew;
    }
}
