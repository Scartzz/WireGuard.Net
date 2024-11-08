using WireGuard.Net.Noise;

namespace WireGuard.Net;

internal class WireGuardState
{
    public required DateTimeOffset Timestamp { get; init; }
    public required DateTimeOffset LastMessage { get; set; }

    public bool IsOlderThan90 => DateTimeOffset.UtcNow - this.Timestamp > TimeSpan.FromSeconds(90);

    public bool IsOlderThan180 => DateTimeOffset.UtcNow - this.Timestamp > TimeSpan.FromSeconds(180);

    public required HandshakeState State { get; init; }

    public uint LocalIndex { get; init; }
    public uint RemoteIndex { get; set; }
    public ulong LocalCounter { get; set; }
    public ulong RemoteCounter { get; set; }
    public Transport? DataTransport { get; set; }
}