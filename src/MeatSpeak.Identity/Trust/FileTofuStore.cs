using System.Text.Json;

namespace MeatSpeak.Identity.Trust;

/// <summary>
/// File-based TOFU store using JSON, similar to SSH known_hosts.
/// </summary>
public sealed class FileTofuStore : ITofuStore
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public FileTofuStore(string filePath)
    {
        _filePath = filePath;
    }

    public async Task<TofuPin?> GetPinAsync(string entityId, CancellationToken ct = default)
    {
        var pins = await LoadAsync(ct);
        return pins.GetValueOrDefault(entityId);
    }

    public async Task SetPinAsync(TofuPin pin, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var pins = await LoadAsync(ct);
            pins[pin.EntityId] = pin;
            await SaveAsync(pins, ct);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<TofuPin>> GetAllPinsAsync(CancellationToken ct = default)
    {
        var pins = await LoadAsync(ct);
        return pins.Values.ToList();
    }

    private async Task<Dictionary<string, TofuPin>> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(_filePath))
            return new Dictionary<string, TofuPin>();

        var json = await File.ReadAllTextAsync(_filePath, ct);
        if (string.IsNullOrWhiteSpace(json))
            return new Dictionary<string, TofuPin>();

        var entries = JsonSerializer.Deserialize<List<TofuPinDto>>(json, JsonOptions);
        if (entries is null)
            return new Dictionary<string, TofuPin>();

        return entries.ToDictionary(
            e => e.EntityId,
            e => new TofuPin(e.EntityId, e.KeyFingerprint,
                e.FirstSeen, (TofuSources)e.Sources));
    }

    private async Task SaveAsync(Dictionary<string, TofuPin> pins, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(_filePath);
        if (dir is not null && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var dtos = pins.Values.Select(p => new TofuPinDto
        {
            EntityId = p.EntityId,
            KeyFingerprint = p.KeyFingerprint,
            FirstSeen = p.FirstSeen,
            Sources = (int)p.Sources,
        }).ToList();

        var json = JsonSerializer.Serialize(dtos, JsonOptions);
        await File.WriteAllTextAsync(_filePath, json, ct);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private sealed class TofuPinDto
    {
        public string EntityId { get; set; } = "";
        public string KeyFingerprint { get; set; } = "";
        public DateTimeOffset FirstSeen { get; set; }
        public int Sources { get; set; }
    }
}
