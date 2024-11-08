using System.Buffers.Binary;
using System.Diagnostics;
using Blake2Fast;
using Org.BouncyCastle.Crypto.Parameters;
using WireGuard.Net.Noise;

namespace WireGuard.Net.Packets;

internal class WireGuardHandshakePacket
{
    private WireGuardHandshakePacket()
    {
        this.Data = new ByteArrayOwnership(1 + 3 + 4 + 32 + 32 + 16 + 12 + 16 + 16 + 16, "HandshakePacket");
        this.Data.WriteAbleSpan.Clear();
    }

    private ByteArrayOwnership Data { get; }

    private byte MessageType
    {
        get => this.Data.ReadOnlySpan[0];
        set => this.Data.WriteAbleSpan[0] = value;
    }

    private Span<byte> ReservedZero
    {
        get => this.Data.WriteAbleSpan.Slice(1, 3);
    }

    private uint SenderIndex
    {
        get => BinaryPrimitives.ReadUInt32LittleEndian(this.Data.ReadOnlySpan.Slice(4, 4));
        set => BinaryPrimitives.WriteUInt32LittleEndian(this.Data.WriteAbleSpan.Slice(4, 4), value);
    }

    private Span<byte> InnerHandshakeSpan
    {
        get => this.Data.WriteAbleSpan.Slice(8, 32 + 32 + 16 + 12 + 16);
    }

    private Span<byte> Mac1Span
    {
        get => this.Data.WriteAbleSpan.Slice(116, 16);
    }

    private Span<byte> Mac2Span
    {
        get => this.Data.WriteAbleSpan.Slice(132, 16);
    }

    private static ByteArrayOwnership GetTai64N()
    {
        var now = DateTimeOffset.UtcNow;
        var buffer = new ByteArrayOwnership(12, "Tai64N");

        BinaryPrimitives.WriteUInt64BigEndian(buffer.WriteAbleSpan, 4611686018427387914ul + (ulong)now.ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32BigEndian(buffer.WriteAbleSpan.Slice(8), (uint)(now.Millisecond * 1e6));

        return buffer;
    }

    private static void GenerateInnerHandshake(HandshakeState handshakeState, Span<byte> innerHandshakeSpan)
    {
        ArgumentNullException.ThrowIfNull(handshakeState, nameof(handshakeState));
        if (innerHandshakeSpan.Length != 32 + 32 + 16 + 12 + 16)
            throw new ArgumentException("Span has invalid Length", nameof(innerHandshakeSpan));
        var payload = GetTai64N();
        try
        {
            var bytesWritten = handshakeState.WriteMessage(payload.ReadOnlySpan, innerHandshakeSpan);
            if (bytesWritten != 32 + 32 + 16 + 12 + 16)
                throw new UnreachableException("Unexpected Length of Encrypted WireGuard Handshake");
        }
        finally
        {
            payload.Dispose();
        }
    }

    private static void GenerateMac1(X25519PublicKeyParameters remotePublicKey, ReadOnlySpan<byte> packet, Span<byte> mac1Span)
    {
        ArgumentNullException.ThrowIfNull(remotePublicKey, nameof(remotePublicKey));
        if (packet.Length != 1 + 3 + 4 + 32 + 32 + 16 + 12 + 16)
            throw new ArgumentException("packet has invalid Length", nameof(packet));
        if (mac1Span.Length != 16)
            throw new ArgumentException("mac1Span has invalid Length", nameof(packet));

        var mac1Header = "mac1----"u8;

        var hasher = Blake2s.CreateIncrementalHasher(32);

        //hasher.Update("mac1----"u8.ToArray().Concat(remotePublicKey).ToArray());
        hasher.Update(mac1Header);
        hasher.Update(remotePublicKey.GetEncoded());

        var mac1Hash = new ByteArrayOwnership(32, "Mac1Hash");

        try
        {
            hasher.Finish(mac1Hash.WriteAbleSpan);

            hasher = Blake2s.CreateIncrementalHasher(16, mac1Hash.ReadOnlySpan);
            hasher.Update(packet);

            hasher.Finish(mac1Span);
        }
        finally
        {
            mac1Hash.Dispose();
        }
    }

    private static void GenerateMac2(byte[] cookie, ReadOnlySpan<byte> packet, Span<byte> mac2Span)
    {
        ArgumentNullException.ThrowIfNull(cookie, nameof(cookie));
        if (packet.Length != 1 + 3 + 4 + 32 + 32 + 16 + 12 + 16 + 16)
            throw new ArgumentException("packet has invalid Length", nameof(packet));
        if (mac2Span.Length != 16)
            throw new ArgumentException("mac2Span has invalid Length", nameof(packet));

        var hasher = Blake2s.CreateIncrementalHasher(16, cookie);
        hasher.Update(packet);
        hasher.Finish(mac2Span);
    }

    public static ByteArrayOwnership GenerateHandshakeAsInitiator(HandshakeState handshakeState, X25519PublicKeyParameters remotePublicKey, uint localIndex)
    {
        var handshakePacket = new WireGuardHandshakePacket();

        handshakePacket.MessageType = 1;
        handshakePacket.ReservedZero.Clear();

        handshakePacket.SenderIndex = localIndex;

        GenerateInnerHandshake(handshakeState, handshakePacket.InnerHandshakeSpan);
        GenerateMac1(remotePublicKey, handshakePacket.Data.ReadOnlySpan[..(1 + 3 + 4 + 32 + 32 + 16 + 12 + 16)], handshakePacket.Mac1Span);

        var cookie = Array.Empty<byte>();
        if (cookie.Length == 0)
            handshakePacket.Mac2Span.Clear();
        else
            GenerateMac2(cookie, handshakePacket.Data.ReadOnlySpan[..(1 + 3 + 4 + 32 + 32 + 16 + 12 + 16 + 16)], handshakePacket.Mac2Span);

        return handshakePacket.Data;
    }
}