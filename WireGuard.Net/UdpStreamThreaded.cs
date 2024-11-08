using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using WireGuard.Net.Noise;
using WireGuard.Net.Packets;

namespace WireGuard.Net;

internal class UdpStreamAsyncStateWrite
{
    public required UdpStreamThreaded UdpStreamThreaded { get; init; }
    public required ByteArrayOwnership Buffer { get; init; }
    public required TaskCompletionSource? Tcs { get; init; }
}

internal class UdpStreamAsyncStateRead
{
    public required UdpStreamThreaded UdpStreamThreaded { get; init; }
    public required ByteArrayOwnership Buffer { get; init; }
}

internal class UdpStreamThreaded : IDisposable
{
    private readonly EndPoint _endPoint;
    private readonly ILogger _logger;
    private readonly ConcurrentQueue<ByteArrayOwnership> _readBuffer;
    private readonly Socket _socket;

    public UdpStreamThreaded(EndPoint endPoint, ILogger logger)
    {
        this._socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        this._socket.Connect(endPoint);

        var resp = new ByteArrayOwnership(Protocol.MaxMessageLength, "ThreadStream-Read");
        this._socket.BeginReceive(resp.Array, 0, resp.Length, SocketFlags.None, ReadCallback, new UdpStreamAsyncStateRead { UdpStreamThreaded = this, Buffer = resp });

        this._endPoint = endPoint;
        this._logger = logger;
        this._readBuffer = new ConcurrentQueue<ByteArrayOwnership>();
        this.Disposed = false;
    }

    public bool Disposed { get; private set; }

    public bool IsReadAvailable => !this._readBuffer.IsEmpty;

    public void Dispose()
    {
        if (this.Disposed) return;
        this.Disposed = true;
        this.ClearBuffer();
        this._socket.Dispose();
        this.ClearBuffer();
    }

    private static void ReadCallback(IAsyncResult ar)
    {
        var readState = (UdpStreamAsyncStateRead)ar.AsyncState!;
        var self = readState.UdpStreamThreaded;
        var buffer = readState.Buffer;
        int readBytes;
        try
        {
            readBytes = readState.UdpStreamThreaded._socket.EndReceive(ar);
        }
        catch (Exception e)
        {
            buffer.Dispose();
            if (!self.Disposed)
            {
                self._logger.LogError(e, "Error while Receive!");
                self.Dispose();
            }
            return;
        }
        if (readBytes == 0)
        {
            buffer.Dispose();
            self.Dispose();
            self._logger.LogInformation("Connection closed!");
            return;
        }

        if (self.Disposed)
        {
            buffer.Dispose();
            self._logger.LogInformation("Connection disposed!");
            return;
        }

        buffer.Shrink(readBytes);
        self._readBuffer.Enqueue(buffer);

        var respNew = new ByteArrayOwnership(Protocol.MaxMessageLength, "ThreadStream-Read");
        self._socket.BeginReceive(respNew.Array, 0, respNew.Length, SocketFlags.None, ReadCallback, new UdpStreamAsyncStateRead { UdpStreamThreaded = self, Buffer = respNew });
    }

    private static void WriteCallback(IAsyncResult ar)
    {
        var readState = (UdpStreamAsyncStateWrite)ar.AsyncState!;
        var self = readState.UdpStreamThreaded;
        var buffer = readState.Buffer;

        try
        {
            readState.UdpStreamThreaded._socket.EndSend(ar);
            readState.Tcs?.TrySetResult();
        }
        catch (Exception e)
        {
            buffer.Dispose();
            self.Dispose();
            self._logger.LogError(e, "Error while Send!");
            readState.Tcs?.TrySetException(e);
            return;
        }

        buffer.Dispose();
    }

    public void QueuePacket(ByteArrayOwnership arrayOwnership, TaskCompletionSource? tcs)
    {
        if (this.Disposed)
            return;
        this._socket.BeginSendTo(arrayOwnership.Array, 0, arrayOwnership.Length, SocketFlags.None, this._endPoint, WriteCallback, new UdpStreamAsyncStateWrite { UdpStreamThreaded = this, Buffer = arrayOwnership, Tcs = tcs });
    }

    public bool TryGetPacket([NotNullWhen(true)] out ByteArrayOwnership? array)
    {
        if (this.Disposed)
        {
            array = null;
            return false;
        }
        return this._readBuffer.TryDequeue(out array);
    }

    private void ClearBuffer()
    {
        while (this._readBuffer.TryDequeue(out var array))
        {
            array.Dispose();
        }
    }
}