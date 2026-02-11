using MeatSpeak.Identity.Crypto;
using MeatSpeak.Identity.Records;
using MeatSpeak.Identity.Resolution;
using MeatSpeak.Identity.Verification;
using NSubstitute;

namespace MeatSpeak.Identity.Tests.Verification;

public class DualSourceVerifierTests
{
    private const string IdentityDomain = "id.example.org";
    private const string ServerDomain = "chat.example.org";
    private const string Kid = "2026-02";

    [Fact]
    public async Task BothSourcesMatch_ReturnsVerified()
    {
        using var serverKey = IdentityKeyPair.Generate();
        var challenge = "test-challenge"u8.ToArray();
        var signature = serverKey.Sign(challenge);
        var serverUid = Uid.NewUid();

        var keyRecord = new KeyRecord(1, "ed25519", Kid, serverKey.PublicKey, Type: EntityType.Server);
        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { keyRecord });
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { keyRecord });

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid, challenge, signature);

        Assert.Equal(VerifyResult.Verified, result);
    }

    [Fact]
    public async Task OnlyIdentityDomain_ReturnsPartial()
    {
        using var serverKey = IdentityKeyPair.Generate();
        var challenge = "test"u8.ToArray();
        var signature = serverKey.Sign(challenge);
        var serverUid = Uid.NewUid();

        var keyRecord = new KeyRecord(1, "ed25519", Kid, serverKey.PublicKey, Type: EntityType.Server);
        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { keyRecord });
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(Array.Empty<KeyRecord>());

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid, challenge, signature);

        Assert.Equal(VerifyResult.Partial, result);
    }

    [Fact]
    public async Task OnlyServerDomain_ReturnsPartial()
    {
        using var serverKey = IdentityKeyPair.Generate();
        var challenge = "test"u8.ToArray();
        var signature = serverKey.Sign(challenge);
        var serverUid = Uid.NewUid();

        var keyRecord = new KeyRecord(1, "ed25519", Kid, serverKey.PublicKey, Type: EntityType.Server);
        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(Array.Empty<KeyRecord>());
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { keyRecord });

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid, challenge, signature);

        Assert.Equal(VerifyResult.Partial, result);
    }

    [Fact]
    public async Task KeysMismatch_ReturnsKeyMismatch()
    {
        using var key1 = IdentityKeyPair.Generate();
        using var key2 = IdentityKeyPair.Generate();
        var challenge = "test"u8.ToArray();
        var signature = key1.Sign(challenge);
        var serverUid = Uid.NewUid();

        var idRecord = new KeyRecord(1, "ed25519", Kid, key1.PublicKey, Type: EntityType.Server);
        var selfRecord = new KeyRecord(1, "ed25519", Kid, key2.PublicKey, Type: EntityType.Server);

        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { idRecord });
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { selfRecord });

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid, challenge, signature);

        Assert.Equal(VerifyResult.KeyMismatch, result);
    }

    [Fact]
    public async Task NoKeys_ReturnsNoKeyFound()
    {
        var serverUid = Uid.NewUid();
        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(Array.Empty<KeyRecord>());
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(Array.Empty<KeyRecord>());

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid,
            "test"u8.ToArray(), new byte[64]);

        Assert.Equal(VerifyResult.NoKeyFound, result);
    }

    [Fact]
    public async Task BadSignature_ReturnsSignatureFailed()
    {
        using var serverKey = IdentityKeyPair.Generate();
        var challenge = "test"u8.ToArray();
        var badSig = new byte[64]; // all zeros = invalid sig
        var serverUid = Uid.NewUid();

        var keyRecord = new KeyRecord(1, "ed25519", Kid, serverKey.PublicKey, Type: EntityType.Server);
        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { keyRecord });
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { keyRecord });

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid, challenge, badSig);

        Assert.Equal(VerifyResult.SignatureFailed, result);
    }

    [Fact]
    public async Task RevokedKey_Skipped()
    {
        using var serverKey = IdentityKeyPair.Generate();
        var serverUid = Uid.NewUid();

        var revokedRecord = new KeyRecord(1, "ed25519", Kid, serverKey.PublicKey,
            Flags: KeyFlags.Revoked, Type: EntityType.Server);

        var resolver = Substitute.For<IIdentityResolver>();
        resolver.ResolveKeysAsync(serverUid, IdentityDomain, Arg.Any<CancellationToken>())
            .Returns(new[] { revokedRecord });
        resolver.ResolveServerKeysAsync(ServerDomain, Arg.Any<CancellationToken>())
            .Returns(Array.Empty<KeyRecord>());

        var verifier = new DualSourceVerifier(resolver);
        var result = await verifier.VerifyServerAsync(
            serverUid, ServerDomain, IdentityDomain, Kid,
            "test"u8.ToArray(), new byte[64]);

        Assert.Equal(VerifyResult.NoKeyFound, result);
    }
}
