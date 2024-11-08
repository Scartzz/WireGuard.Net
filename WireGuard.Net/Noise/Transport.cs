using System.Diagnostics;
using WireGuard.Net.Noise.Statics;
using WireGuard.Net.Packets;

namespace WireGuard.Net.Noise;

/// <summary>
///     A pair of <see href="https://noiseprotocol.org/noise.html#the-cipherstate-object">CipherState</see>
///     objects for encrypting transport messages.
/// </summary>
internal sealed class Transport
{
    private readonly CipherState _c1;
    private readonly CipherState? _c2;
    private readonly bool _initiator;

    public Transport(bool initiator, CipherState c1, CipherState? c2)
    {
        ArgumentNullException.ThrowIfNull(c1);

        this._initiator = initiator;
        this._c1 = c1;
        this._c2 = c2;
    }

    public bool IsOneWay
    {
        get => this._c2 == null;
    }

    /// <summary>
    ///     Encrypts the <paramref name="payload" /> and writes the result into <paramref name="messageBuffer" />.
    /// </summary>
    /// <param name="payload">The payload to encrypt.</param>
    /// <param name="messageBuffer">The buffer for the encrypted message.</param>
    /// <returns>The ciphertext size in bytes.</returns>
    /// <exception cref="ObjectDisposedException">
    ///     Thrown if the current instance has already been disposed.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///     Thrown if the responder has attempted to write a message to a one-way stream.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Thrown if the encrypted payload was greater than <see cref="Protocol.MaxMessageLength" />
    ///     bytes in length, or if the output buffer did not have enough space to hold the ciphertext.
    /// </exception>
    public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer)
    {
        if (!this._initiator && this.IsOneWay)
        {
            throw new InvalidOperationException("Responder cannot write messages to a one-way stream.");
        }

        if (payload.Length + Aead.TagSize > Protocol.MaxMessageLength)
        {
            throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
        }

        if (payload.Length + Aead.TagSize > messageBuffer.Length)
        {
            throw new ArgumentException("Message buffer does not have enough space to hold the ciphertext.");
        }

        var cipher = this._initiator ? this._c1 : this._c2;

        Debug.Assert(cipher?.HasKey() ?? false);

        return cipher.EncryptWithAd(null, payload, messageBuffer);
    }

    /// <summary>
    ///     Decrypts the <paramref name="message" /> and returns the result as ArrayOwnership
    /// </summary>
    /// <param name="message">The message to decrypt.</param>
    /// <returns>The plaintext in bytes as ArrayOwnership.</returns>
    /// <exception cref="ObjectDisposedException">
    ///     Thrown if the current instance has already been disposed.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///     Thrown if the initiator has attempted to read a message from a one-way stream.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Thrown if the message was greater than <see cref="Protocol.MaxMessageLength" />
    ///     bytes in length, or if the output buffer did not have enough space to hold the plaintext.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    ///     Thrown if the decryption of the message has failed.
    /// </exception>
    public ByteArrayOwnership ReadMessage(ReadOnlySpan<byte> message)
    {
        if (this._initiator && this.IsOneWay)
        {
            throw new InvalidOperationException("Initiator cannot read messages from a one-way stream.");
        }

        if (message.Length > Protocol.MaxMessageLength)
        {
            throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
        }

        if (message.Length < Aead.TagSize)
        {
            throw new ArgumentException($"Noise message must be greater than or equal to {Aead.TagSize} bytes in length.");
        }

        var decryptedSize = message.Length - Aead.TagSize;

        var result = new ByteArrayOwnership(decryptedSize, "Transport-DecryptedMessage");
        try
        {

            var cipher = this._initiator ? this._c2 : this._c1;
            Debug.Assert(cipher?.HasKey() ?? false);

            var bytesWritten = cipher.DecryptWithAd(null, message, result.WriteAbleSpan);

            if (bytesWritten != decryptedSize)
                throw new InvalidOperationException("BytesWritten and decryptedSize are not equal!");
        }
        catch
        {
            result.Dispose();
            throw;
        }

        return result;
    }
}