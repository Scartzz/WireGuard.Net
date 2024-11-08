using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;
using WireGuard.Net.Extensions;
using WireGuard.Net.Noise;
using WireGuard.Net.Packets;

namespace WireGuard.Net;

public class WireGuardConnection : IDisposable
{
    private readonly SimpleTimer _betterTimer;
    private readonly DateTimeOffset _creationTime;
    private readonly ILogger<WireGuardConnection> _logger;
    private readonly Action<ByteArrayOwnership> _packetHandler;

    private readonly ConcurrentQueue<(ByteArrayOwnership Data, TaskCompletionSource? Tcs)> _writeBuffer;
    private WireGuardState? _current;
    private WireGuardState? _next;

    private WireGuardState? _old;

    private UdpStreamThreaded? _stream;

    public WireGuardConnection(WireGuardSettings connectionDetails, Action<ByteArrayOwnership> packetHandler, ILogger<WireGuardConnection> logger)
    {
        this.ConnectionDetails = connectionDetails;
        this._creationTime = DateTimeOffset.UtcNow;
        this._packetHandler = packetHandler;
        this._logger = logger;
        this._writeBuffer = new ConcurrentQueue<(ByteArrayOwnership, TaskCompletionSource?)>();
        this._betterTimer = new SimpleTimer(1, this.SocketTimer);
    }

    private static (WireGuardState, ByteArrayOwnership) InitiateNewState(WireGuardSettings connectionDetails)
    {
        var handshakeState = new HandshakeState(
            true,
            connectionDetails.LocalKeyPair,
            connectionDetails.ServerKey,
            new[] { new byte[32] });

        var localIndex = (uint)Random.Shared.Next(1, int.MaxValue);

        var handshakeMessage = WireGuardHandshakePacket.GenerateHandshakeAsInitiator(handshakeState, connectionDetails.ServerKey, localIndex);

        var wireGuardState = new WireGuardState
        {
            Timestamp = DateTime.UtcNow,
            LastMessage = DateTime.UtcNow,
            LocalIndex = localIndex,
            State = handshakeState,
            RemoteIndex = 0,
            LocalCounter = 0,
            RemoteCounter = 0,
        };

        return (wireGuardState, handshakeMessage);
    }

    private bool TryRead(CancellationToken cancellationToken)
    {
        if (this._stream!.Disposed)
            return false;
        if (!this._stream.IsReadAvailable)
            return true;

        while (this._stream.TryGetPacket(out var resp))
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (resp.ReadOnlySpan[1] != 0 || resp.ReadOnlySpan[2] != 0 || resp.ReadOnlySpan[3] != 0)
                    throw new InvalidOperationException("Packet from Server has not reserved Fields!");

                var packetType = resp.ReadOnlySpan[0];

                uint myIndex = 0;
                WireGuardState? contextState = null;
                if (packetType == 2)
                {
                    myIndex = BinaryPrimitives.ReadUInt32LittleEndian(resp.ReadOnlySpan.Slice(8, 4));
                    if (this._old is not null && this._old.LocalIndex == myIndex)
                    {
                        contextState = this._old;
                    }
                    else if (this._current is not null && this._current.LocalIndex == myIndex)
                    {
                        contextState = this._current;
                    }
                    else if (this._next is not null && this._next.LocalIndex == myIndex)
                    {
                        contextState = this._next;
                    }
                    if (contextState is null)
                    {
                        continue;
                    }
                }
                else if (packetType == 4)
                {
                    myIndex = BinaryPrimitives.ReadUInt32LittleEndian(resp.ReadOnlySpan.Slice(4, 4));
                    if (this._old is not null && this._old.LocalIndex == myIndex)
                    {
                        contextState = this._old;
                    }
                    else if (this._current is not null && this._current.LocalIndex == myIndex)
                    {
                        contextState = this._current;
                    }
                    else if (this._next is not null && this._next.LocalIndex == myIndex)
                    {
                        contextState = this._next;
                    }
                    if (contextState is null)
                    {
                        continue;
                    }
                }
                else
                {
                    continue;
                }

                return this.HandlePacketForState(contextState, resp);
            }
            catch (Exception e2)
            {
                this._logger.LogWarning("Exception: {Ex}", e2.ToString());
                return false;
            }
            finally
            {
                resp.Dispose();
            }
        }

        return !this._stream.Disposed;
    }

    private bool HandlePacketForState(WireGuardState state, ByteArrayOwnership resp)
    {
        this._logger.LogDebug($"WG-Message: {resp.Length}; {resp.ReadOnlySpan[0]}; {state.RemoteCounter}");

        if (resp.ReadOnlySpan[0] == 2 && state.DataTransport is null)
        {
            if (resp.Length != 92)
                throw new InvalidOperationException("Handshake Resp from Server is not 92-Length!");

            state.RemoteIndex = BinaryPrimitives.ReadUInt32LittleEndian(resp.ReadOnlySpan.Slice(4, 4));
            var respReceiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(resp.ReadOnlySpan.Slice(8, 4));
            if (respReceiverIndex != state.LocalIndex)
                throw new InvalidOperationException("Handshake from Server has not correct Indexes!");
            (var bytesReadInner, state.DataTransport) = state.State.ReadMessage(resp.ReadOnlySpan.Slice(12, 48), Span<byte>.Empty);
            if (bytesReadInner != 0)
                throw new InvalidOperationException("Handshake from Server unexpected payload!");

            state.LastMessage = DateTime.UtcNow;

            return true;
        }

        if (resp.ReadOnlySpan[0] == 4 && state.DataTransport is not null)
        {
            state.LastMessage = DateTime.UtcNow;

            var respReceiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(resp.ReadOnlySpan.Slice(4, 4));
            if (respReceiverIndex != state.LocalIndex)
                throw new InvalidOperationException("Data from Server has not correct Indexes!");
            var remoteCounter = BinaryPrimitives.ReadUInt64LittleEndian(resp.ReadOnlySpan.Slice(8, 8));
            if (state.RemoteCounter != remoteCounter)
            {
                this._logger.LogError($"Data from Server has not correct Counter (My: {state.RemoteCounter}; There: {remoteCounter})!");
                return false;
            }

            var arrayOwnership2 = state.DataTransport.ReadMessage(resp.ReadOnlySpan.Slice(16));
            try
            {
                //this._logger.LogDebug("Recv Data {Byte}", arrayOwnership2.Base64);
                this._packetHandler(arrayOwnership2);
            }
            finally
            {
                arrayOwnership2.Dispose();
            }
        }

        state.RemoteCounter += 1;

        return true;
    }

    private async Task CheckStream(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (this._stream is null)
        {
            this._logger.LogDebug("Stream is not ready. Create...");
            cancellationToken.ThrowIfCancellationRequested();
            this._stream = new UdpStreamThreaded(new IPEndPoint(IPAddress.Parse(this.ConnectionDetails.ServerIp), this.ConnectionDetails.ServerPort), this._logger);
            cancellationToken.ThrowIfCancellationRequested();
        }

        if (this._stream.Disposed)
        {
            this._logger.LogWarning("Stream is disposed. Destroying Stream...");
            this._stream = null;
            cancellationToken.ThrowIfCancellationRequested();
            await this.CheckStream(cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private void CheckOlderThan180()
    {
        if (this._old is not null && this._old.IsOlderThan180)
        {
            this._logger.LogInformation("Old is older than 180. Destroying Old!");
            this._old = null;
        }
        if (this._current is not null && this._current.IsOlderThan180)
        {
            this._logger.LogInformation("Current is older than 180. Destroying Current!");
            this._current = null;
        }
        if (this._next is not null && this._next.IsOlderThan180)
        {
            this._logger.LogInformation("Next is older than 180. Destroying Next!");
            this._next = null;
        }
    }

    private void CheckStates(CancellationToken cancellationToken)
    {
        this.CheckOlderThan180();

        if (this._current is null)
        {
            this._logger.LogDebug("No State is ready. Kicking off Current...");
            cancellationToken.ThrowIfCancellationRequested();
            (this._current, var handshakeMessage) = InitiateNewState(this.ConnectionDetails);
            (this._stream ?? throw new UnreachableException("Stream is null!!!")).QueuePacket(handshakeMessage, null);
            cancellationToken.ThrowIfCancellationRequested();
        }

        if (this._current.IsOlderThan90)
        {
            if (this._next is null)
            {
                this._logger.LogDebug("Next State is not ready. Kicking off Next...");
                cancellationToken.ThrowIfCancellationRequested();
                (this._next, var handshakeMessage) = InitiateNewState(this.ConnectionDetails);
                (this._stream ?? throw new UnreachableException("Stream is null!!!")).QueuePacket(handshakeMessage, null);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        if (this._next is not null && this._next.DataTransport is not null)
        {
            this._logger.LogDebug("Next State is ready. Switching...");

            if (this._old is not null)
            {
                this._logger.LogDebug("Killing Old!");
            }

            this._old = this._current;
            this._current = this._next;
            this._next = null;
        }
    }

    private async Task SocketTimer(CancellationToken cancellationToken)
    {
        await this.CheckStream(cancellationToken).ConfigureAwait(false);
        this.CheckStates(cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        var socketAllOk = this.TryRead(cancellationToken);
        if (!socketAllOk)
        {
            this._logger.LogError("Read returned error. Destroying everything!");
            this._stream?.Dispose();
            this._old = null;
            this._current = null;
            this._next = null;
            this._stream = null;
            cancellationToken.ThrowIfCancellationRequested();
            await this.SocketTimer(cancellationToken).ConfigureAwait(false);
            return;
        }
        cancellationToken.ThrowIfCancellationRequested();

        this.CheckStates(cancellationToken);

        if (this._current is not null && this._current.DataTransport is null && this._current.LastMessage.IsLaterThan(TimeSpan.FromSeconds(5)))
        {
            this._logger.LogInformation("Current was kicked off but no Response was received. Destroying Current!");
            this._current = null;
            cancellationToken.ThrowIfCancellationRequested();
            await this.SocketTimer(cancellationToken).ConfigureAwait(false);
            return;
        }
        if (this._next is not null && this._next.DataTransport is null && this._next.LastMessage.IsLaterThan(TimeSpan.FromSeconds(5)))
        {
            this._logger.LogInformation("Next was kicked off but no Response was received. Destroying Next!");
            this._next = null;
            cancellationToken.ThrowIfCancellationRequested();
            await this.SocketTimer(cancellationToken).ConfigureAwait(false);
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (this._current?.DataTransport is null)
            return;

        var activeState = this._current;

        if (!this._writeBuffer.IsEmpty)
        {
            while (activeState?.DataTransport is not null && this._writeBuffer.TryDequeue(out var toWriteTuple))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var packet = WireGuardTransportPacket.GenerateTransport(activeState.DataTransport, toWriteTuple.Data.ReadOnlySpan, activeState.RemoteIndex, activeState.LocalCounter++);

                //this._logger.LogDebug("Send Data {Byte}", toWrite.Base64);

                toWriteTuple.Data.Dispose();

                activeState.LastMessage = DateTime.UtcNow;

                cancellationToken.ThrowIfCancellationRequested();

                this._logger.LogDebug("Send Data {Byte}", packet.Length);

                this._stream!.QueuePacket(packet, toWriteTuple.Tcs);

                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        if (activeState?.DataTransport is not null && activeState.LastMessage.IsLaterThan(TimeSpan.FromSeconds(10)))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var packet = WireGuardTransportPacket.GenerateTransport(activeState.DataTransport, ReadOnlySpan<byte>.Empty, activeState.RemoteIndex, activeState.LocalCounter++);

            activeState.LastMessage = DateTime.UtcNow;
            cancellationToken.ThrowIfCancellationRequested();
            this._logger.LogDebug("Send Keepalive {Byte}", packet.Length);
            this._stream!.QueuePacket(packet, null);
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    public WireGuardSettings ConnectionDetails { get; }

    public void QueuePacket(ByteArrayOwnership byteArrayOwnership, TaskCompletionSource? tcs)
    {
        this._writeBuffer.Enqueue((byteArrayOwnership, tcs));
    }

    public DateTimeOffset LastActivityTime
    {
        get
        {
            var newest = this._creationTime;
            if (this._old is not null)
            {
                if (this._old.LastMessage > newest)
                {
                    newest = this._old.LastMessage;
                }
            }
            if (this._current is not null)
            {
                if (this._current.LastMessage > newest)
                {
                    newest = this._current.LastMessage;
                }
            }
            if (this._next is not null)
            {
                if (this._next.LastMessage > newest)
                {
                    newest = this._next.LastMessage;
                }
            }
            return newest;
        }
    }

    public void Dispose()
    {
        this._logger.LogInformation("Dispose WG Connection");
        this._betterTimer.Dispose();

        this._old = null;
        this._current = null;
        this._next = null;

        this._stream?.Dispose();

        while (this._writeBuffer.TryDequeue(out var missedOut))
        {
            missedOut.Data.Dispose();
            missedOut.Tcs?.TrySetException(new ObjectDisposedException(nameof(WireGuardConnection)));
        }
    }
}