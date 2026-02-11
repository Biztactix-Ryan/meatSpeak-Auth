using MeatSpeak.Identity.Auth;
using MeatSpeak.Identity.Crypto;

namespace MeatSpeak.Identity.Tests.Auth;

public class MutualAuthTests
{
    [Fact]
    public void ServerHello_CreateAndVerify()
    {
        using var serverKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();

        var hello = MutualAuth.CreateServerHello(serverUid, "2026-02", serverKey);

        Assert.Equal(serverUid, hello.ServerUid);
        Assert.Equal("2026-02", hello.Kid);
        Assert.Equal(16, hello.Nonce.Length);
        Assert.True(MutualAuth.VerifyServerHello(hello, serverKey.PublicKey));
    }

    [Fact]
    public void ServerHello_WrongKey_FailsVerification()
    {
        using var serverKey = IdentityKeyPair.Generate();
        using var wrongKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();

        var hello = MutualAuth.CreateServerHello(serverUid, "2026-02", serverKey);

        Assert.False(MutualAuth.VerifyServerHello(hello, wrongKey.PublicKey));
    }

    [Fact]
    public void ClientHello_CreateAndVerify()
    {
        using var serverKey = IdentityKeyPair.Generate();
        using var userKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();
        var userUid = Uid.NewUid();

        var serverHello = MutualAuth.CreateServerHello(serverUid, "2026-02", serverKey);
        var clientHello = MutualAuth.CreateClientHello(
            userUid, "2026-02", userKey, serverHello.Nonce, serverUid);

        Assert.Equal(userUid, clientHello.UserUid);
        Assert.Equal(16, clientHello.Nonce.Length);
        Assert.True(MutualAuth.VerifyClientHello(
            clientHello, userKey.PublicKey, serverHello.Nonce, serverUid));
    }

    [Fact]
    public void ClientHello_WrongServerNonce_FailsVerification()
    {
        using var serverKey = IdentityKeyPair.Generate();
        using var userKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();
        var userUid = Uid.NewUid();

        var serverHello = MutualAuth.CreateServerHello(serverUid, "2026-02", serverKey);
        var clientHello = MutualAuth.CreateClientHello(
            userUid, "2026-02", userKey, serverHello.Nonce, serverUid);

        var wrongNonce = new byte[16];
        Assert.False(MutualAuth.VerifyClientHello(
            clientHello, userKey.PublicKey, wrongNonce, serverUid));
    }

    [Fact]
    public void ClientHello_WrongServerUid_FailsVerification()
    {
        using var serverKey = IdentityKeyPair.Generate();
        using var userKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();
        var wrongServerUid = Uid.NewUid();
        var userUid = Uid.NewUid();

        var serverHello = MutualAuth.CreateServerHello(serverUid, "2026-02", serverKey);
        var clientHello = MutualAuth.CreateClientHello(
            userUid, "2026-02", userKey, serverHello.Nonce, serverUid);

        Assert.False(MutualAuth.VerifyClientHello(
            clientHello, userKey.PublicKey, serverHello.Nonce, wrongServerUid));
    }

    [Fact]
    public void FullHandshake_MutualVerification()
    {
        using var serverKey = IdentityKeyPair.Generate();
        using var userKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();
        var userUid = Uid.NewUid();

        // Step 1: Server sends ServerHello
        var serverHello = MutualAuth.CreateServerHello(serverUid, "srv-key", serverKey);

        // Step 2: Client verifies ServerHello
        Assert.True(MutualAuth.VerifyServerHello(serverHello, serverKey.PublicKey));

        // Step 3: Client sends ClientHello
        var clientHello = MutualAuth.CreateClientHello(
            userUid, "usr-key", userKey, serverHello.Nonce, serverUid);

        // Step 4: Server verifies ClientHello
        Assert.True(MutualAuth.VerifyClientHello(
            clientHello, userKey.PublicKey, serverHello.Nonce, serverUid));
    }
}
