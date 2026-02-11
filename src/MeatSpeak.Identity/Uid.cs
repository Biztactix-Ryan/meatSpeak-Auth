using Cysharp;

namespace MeatSpeak.Identity;

/// <summary>
/// ULID-based unique identifier for MeatSpeak entities.
/// Crockford Base32 encoded, 26 characters, case-insensitive.
/// </summary>
public readonly struct Uid : IEquatable<Uid>, IComparable<Uid>
{
    private readonly Ulid _value;

    private Uid(Ulid value) => _value = value;

    public static Uid NewUid() => new(Ulid.NewUlid());

    public static Uid Parse(string s) => new(Ulid.Parse(s));

    public static bool TryParse(string? s, out Uid result)
    {
        if (Ulid.TryParse(s, out var ulid))
        {
            result = new Uid(ulid);
            return true;
        }
        result = default;
        return false;
    }

    public DateTimeOffset Timestamp => _value.Time;

    public override string ToString() => _value.ToString().ToLowerInvariant();

    public bool Equals(Uid other) => _value == other._value;
    public override bool Equals(object? obj) => obj is Uid other && Equals(other);
    public override int GetHashCode() => _value.GetHashCode();
    public int CompareTo(Uid other) => _value.CompareTo(other._value);

    public static bool operator ==(Uid left, Uid right) => left.Equals(right);
    public static bool operator !=(Uid left, Uid right) => !left.Equals(right);

    public byte[] ToByteArray()
    {
        var bytes = new byte[16];
        _value.TryWriteBytes(bytes);
        return bytes;
    }
}
