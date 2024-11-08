using System.Buffers;

namespace WireGuard.Net.Packets;

public class ByteArrayOwnership : IDisposable
{
    private readonly string _name;
    private readonly byte[] _array;
    private bool _disposed;

    public ByteArrayOwnership(int length, string name)
    {
        this._name = name;
        this._array = ArrayPool<byte>.Shared.Rent(length);
        this._disposed = false;
        this.Length = length;
    }

    ~ByteArrayOwnership()
    {
        Console.WriteLine($"WARNING: ByteArray ({this._name}) not disposed!");
        this._disposed = true;
        ArrayPool<byte>.Shared.Return(this._array);
    }

    public void Shrink(int newLength)
    {
        ObjectDisposedException.ThrowIf(this._disposed, this);
        if (newLength >= this.Length)
            throw new InvalidOperationException(newLength.ToString());
        this.Length = newLength;
    }
    
    public int Length { get; private set; }

    internal byte[] Array
    {
        get
        {
            ObjectDisposedException.ThrowIf(this._disposed, this);
            return this._array;
        }
    }
    
    public Span<byte> WriteAbleSpan
    {
        get
        {
            ObjectDisposedException.ThrowIf(this._disposed, this);
            return new Span<byte>(this._array, 0, this.Length);
        }
    }

    public ReadOnlySpan<byte> ReadOnlySpan
    {
        get
        {
            ObjectDisposedException.ThrowIf(this._disposed, this);
            return new ReadOnlySpan<byte>(this._array, 0, this.Length);
        }
    }

    public void Dispose()
    {
        if (this._disposed)
            return;
        this._disposed = true;
        ArrayPool<byte>.Shared.Return(this._array);
        GC.SuppressFinalize(this);
    }
    
    public override string ToString()
    {
        return $"Bytes(Name: {this._name}; Length: {this.Length})";
    }
}