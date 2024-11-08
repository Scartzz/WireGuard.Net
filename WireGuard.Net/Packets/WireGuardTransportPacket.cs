using System.Buffers.Binary;
using WireGuard.Net.Noise;
using WireGuard.Net.Noise.Statics;

namespace WireGuard.Net.Packets;

internal class WireGuardTransportPacket
{
    private WireGuardTransportPacket(int plainTextSize)
    {
        var encryptedMessageSize = plainTextSize + Aead.TagSize;
        var fullSize = encryptedMessageSize + 16;

        if (fullSize > Protocol.MaxMessageLength)
            throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");

        this.Data = new ByteArrayOwnership(fullSize, "TransportPacket");
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

    private uint RemoteIndex
    {
        get => BinaryPrimitives.ReadUInt32LittleEndian(this.Data.ReadOnlySpan.Slice(4, 4));
        set => BinaryPrimitives.WriteUInt32LittleEndian(this.Data.WriteAbleSpan.Slice(4, 4), value);
    }

    private ulong LocalCounter
    {
        get => BinaryPrimitives.ReadUInt64LittleEndian(this.Data.ReadOnlySpan.Slice(8, 8));
        set => BinaryPrimitives.WriteUInt64LittleEndian(this.Data.WriteAbleSpan.Slice(8, 8), value);
    }

    private Span<byte> Body
    {
        get => this.Data.WriteAbleSpan.Slice(16);
    }

    public static ByteArrayOwnership GenerateTransport(Transport transport, ReadOnlySpan<byte> message, uint remoteIndex, ulong localCounter)
    {
        var transportPacket = new WireGuardTransportPacket(message.Length);

        transportPacket.MessageType = 4;
        transportPacket.ReservedZero.Clear();

        transportPacket.RemoteIndex = remoteIndex;
        transportPacket.LocalCounter = localCounter;

        var bytesWritten = transport.WriteMessage(message, transportPacket.Body);

        if (bytesWritten != message.Length + Aead.TagSize)
            throw new InvalidOperationException("Invalid Encrypted Written Size!");

        return transportPacket.Data;
    }
}