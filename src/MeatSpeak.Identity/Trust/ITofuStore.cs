namespace MeatSpeak.Identity.Trust;

/// <summary>
/// Interface for persisting TOFU (Trust On First Use) key pins.
/// </summary>
public interface ITofuStore
{
    Task<TofuPin?> GetPinAsync(string entityId, CancellationToken ct = default);
    Task SetPinAsync(TofuPin pin, CancellationToken ct = default);
    Task<IReadOnlyList<TofuPin>> GetAllPinsAsync(CancellationToken ct = default);
}

public sealed record TofuPin(
    string EntityId,
    string KeyFingerprint,
    DateTimeOffset FirstSeen,
    TofuSources Sources);

[Flags]
public enum TofuSources
{
    None = 0,
    IdentityDomain = 1,
    ServerDomain = 2,
}
