using MeatSpeak.Identity.Crypto;
using MeatSpeak.Identity.Trust;

namespace MeatSpeak.Identity.Tests.Trust;

public class TofuVerifierTests
{
    [Fact]
    public async Task Verify_FirstUse_PinsKey()
    {
        var store = new FileTofuStore(GetTempPath());
        var verifier = new TofuVerifier(store);
        using var kp = IdentityKeyPair.Generate();

        var result = await verifier.VerifyAsync("server-1", kp.PublicKey,
            TofuSources.IdentityDomain);

        Assert.Equal(TofuResult.TrustedFirstUse, result);

        var pin = await store.GetPinAsync("server-1");
        Assert.NotNull(pin);
        Assert.Equal(TofuVerifier.ComputeFingerprint(kp.PublicKey), pin.KeyFingerprint);
    }

    [Fact]
    public async Task Verify_SameKey_ReturnsPinMatch()
    {
        var store = new FileTofuStore(GetTempPath());
        var verifier = new TofuVerifier(store);
        using var kp = IdentityKeyPair.Generate();

        await verifier.VerifyAsync("server-1", kp.PublicKey, TofuSources.IdentityDomain);
        var result = await verifier.VerifyAsync("server-1", kp.PublicKey,
            TofuSources.IdentityDomain);

        Assert.Equal(TofuResult.TrustedPinMatch, result);
    }

    [Fact]
    public async Task Verify_DifferentKey_ReturnsKeyChanged()
    {
        var store = new FileTofuStore(GetTempPath());
        var verifier = new TofuVerifier(store);
        using var kp1 = IdentityKeyPair.Generate();
        using var kp2 = IdentityKeyPair.Generate();

        await verifier.VerifyAsync("server-1", kp1.PublicKey, TofuSources.IdentityDomain);
        var result = await verifier.VerifyAsync("server-1", kp2.PublicKey,
            TofuSources.IdentityDomain);

        Assert.Equal(TofuResult.KeyChanged, result);
    }

    [Fact]
    public async Task FileTofuStore_PersistsAcrossInstances()
    {
        var path = GetTempPath();
        using var kp = IdentityKeyPair.Generate();

        var store1 = new FileTofuStore(path);
        var verifier1 = new TofuVerifier(store1);
        await verifier1.VerifyAsync("server-1", kp.PublicKey, TofuSources.ServerDomain);

        var store2 = new FileTofuStore(path);
        var pin = await store2.GetPinAsync("server-1");
        Assert.NotNull(pin);
        Assert.Equal(TofuSources.ServerDomain, pin.Sources);
    }

    [Fact]
    public void ComputeFingerprint_Deterministic()
    {
        var key = new byte[32];
        Random.Shared.NextBytes(key);

        var fp1 = TofuVerifier.ComputeFingerprint(key);
        var fp2 = TofuVerifier.ComputeFingerprint(key);

        Assert.Equal(fp1, fp2);
        Assert.Equal(64, fp1.Length); // 32 bytes hex = 64 chars
    }

    private static string GetTempPath() =>
        Path.Combine(Path.GetTempPath(), $"tofu-test-{Guid.NewGuid():N}.json");
}
