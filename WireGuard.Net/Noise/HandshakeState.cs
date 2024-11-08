using System.Diagnostics;
using Org.BouncyCastle.Crypto.Parameters;
using WireGuard.Net.Noise.Enums;
using WireGuard.Net.Noise.Statics;
using WireGuard.Net.Packets;

namespace WireGuard.Net.Noise;

internal sealed class HandshakeState
{
    private readonly Curve25519 _dh = new Curve25519();
    private readonly Role _initiator;
    private readonly bool _isOneWay;
    private readonly bool _isPsk;
    private readonly Queue<MessagePattern> _messagePatterns = new Queue<MessagePattern>();
    private readonly Queue<byte[]> _psks = new Queue<byte[]>();
    private readonly Role _role;
    private readonly X25519KeyPair _s;
    private readonly SymmetricState _state;
    private X25519KeyPair? _e;
    private X25519PublicKeyParameters? _re;
    private X25519PublicKeyParameters _rs;

    private bool _turnToWrite;

    public HandshakeState(
        bool initiator,
        X25519KeyPair localKeyPair,
        X25519PublicKeyParameters remotePublicKey,
        IEnumerable<byte[]> psks)
    {
        var handshakePattern = HandshakePattern.Ik;
        var patternModifiers = PatternModifiers.Psk2;
        var protocolName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"u8;
        var prologue = "WireGuard v1 zx2c4 Jason@zx2c4.com"u8;

        Debug.Assert(psks != null);

        this._state = new SymmetricState(protocolName);
        this._state.MixHash(prologue);

        this._role = initiator ? Role.Alice : Role.Bob;
        this._initiator = Role.Alice;
        this._turnToWrite = initiator;
        this._s = localKeyPair;
        this._rs = remotePublicKey;

        this.ProcessPreMessages(handshakePattern);
        this.ProcessPreSharedKeys(handshakePattern, patternModifiers, psks);

        this._isPsk = true;
        this._isOneWay = this._messagePatterns.Count == 1;
    }

    private void ProcessPreMessages(HandshakePattern handshakePattern)
    {
        foreach (var token in handshakePattern.Initiator.Tokens)
        {
            if (token == Token.S)
            {
                this._state.MixHash((this._role == Role.Alice ? this._s.Public : this._rs).GetEncoded());
            }
        }

        foreach (var token in handshakePattern.Responder.Tokens)
        {
            if (token == Token.S)
            {
                this._state.MixHash((this._role == Role.Alice ? this._rs : this._s.Public).GetEncoded());
            }
        }
    }

    private void ProcessPreSharedKeys(HandshakePattern protocolHandshakePattern, PatternModifiers protocolPatternModifiers, IEnumerable<byte[]> psks)
    {
        var patterns = protocolHandshakePattern.Patterns;
        var modifiers = protocolPatternModifiers;
        var position = 0;

        using (var enumerator = psks.GetEnumerator())
        {
            foreach (var pattern in patterns)
            {
                var modified = pattern;

                if (position == 0 && modifiers.HasFlag(PatternModifiers.Psk0))
                {
                    modified = modified.PrependPsk();
                    this.ProcessPreSharedKey(enumerator);
                }

                if (((int)modifiers & (int)PatternModifiers.Psk1 << position) != 0)
                {
                    modified = modified.AppendPsk();
                    this.ProcessPreSharedKey(enumerator);
                }

                this._messagePatterns.Enqueue(modified);
                ++position;
            }

            if (enumerator.MoveNext())
            {
                throw new ArgumentException("Number of pre-shared keys was greater than the number of PSK modifiers.");
            }
        }
    }

    private void ProcessPreSharedKey(IEnumerator<byte[]> enumerator)
    {
        if (!enumerator.MoveNext())
        {
            throw new ArgumentException("Number of pre-shared keys was less than the number of PSK modifiers.");
        }

        var psk = enumerator.Current;

        if (psk.Length != Aead.KeySize)
        {
            throw new ArgumentException($"Pre-shared keys must be {Aead.KeySize} bytes in length.");
        }

        this._psks.Enqueue(psk.AsSpan().ToArray());
    }

    public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer)
    {
        if (this._messagePatterns.Count == 0)
        {
            throw new InvalidOperationException("Cannot call WriteMessage after the handshake has already been completed.");
        }

        var overhead = this._messagePatterns.Peek().Overhead(this._dh.DhLen, this._state.HasKey(), this._isPsk);
        var ciphertextSize = payload.Length + overhead;

        if (ciphertextSize > Protocol.MaxMessageLength)
        {
            throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
        }

        if (ciphertextSize > messageBuffer.Length)
        {
            throw new ArgumentException("Message buffer does not have enough space to hold the ciphertext.");
        }

        if (!this._turnToWrite)
        {
            throw new InvalidOperationException("Unexpected call to WriteMessage (should be ReadMessage).");
        }

        var next = this._messagePatterns.Dequeue();
        var messageBufferLength = messageBuffer.Length;

        foreach (var token in next.Tokens)
        {
            switch (token)
            {
                case Token.E:
                    messageBuffer = this.WriteE(messageBuffer);
                    break;
                case Token.S:
                    messageBuffer = this.WriteS(messageBuffer);
                    break;
                case Token.Ee:
                    this.DhAndMixKey(this._e, this._re ?? throw new InvalidOperationException("_re cannot be null"));
                    break;
                case Token.Es:
                    this.ProcessEs();
                    break;
                case Token.Se:
                    this.ProcessSe();
                    break;
                case Token.Ss:
                    this.DhAndMixKey(this._s, this._rs);
                    break;
                case Token.Psk:
                    this.ProcessPsk();
                    break;
            }
        }

        var bytesWritten = this._state.EncryptAndHash(payload, messageBuffer);
        var size = messageBufferLength - messageBuffer.Length + bytesWritten;

        Debug.Assert(ciphertextSize == size);

        this._turnToWrite = false;
        return ciphertextSize;
    }

    private Span<byte> WriteE(Span<byte> buffer)
    {
        Debug.Assert(this._e == null);

        this._e = this._dh.GenerateKeyPair();

        var publicEncoded = this._e.Public.GetEncoded();

        publicEncoded.CopyTo(buffer);
        this._state.MixHash(publicEncoded);

        if (this._isPsk)
        {
            this._state.MixKey(publicEncoded);
        }

        return buffer.Slice(publicEncoded.Length);
    }

    private Span<byte> WriteS(Span<byte> buffer)
    {
        Debug.Assert(this._s != null);

        var bytesWritten = this._state.EncryptAndHash(this._s.Public.GetEncoded(), buffer);
        return buffer.Slice(bytesWritten);
    }

    public (int, Transport?) ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer)
    {
        if (this._messagePatterns.Count == 0)
        {
            throw new InvalidOperationException("Cannot call WriteMessage after the handshake has already been completed.");
        }

        var overhead = this._messagePatterns.Peek().Overhead(this._dh.DhLen, this._state.HasKey(), this._isPsk);
        var plaintextSize = message.Length - overhead;

        if (message.Length > Protocol.MaxMessageLength)
        {
            throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
        }

        if (message.Length < overhead)
        {
            throw new ArgumentException($"Noise message must be greater than or equal to {overhead} bytes in length.");
        }

        if (plaintextSize > payloadBuffer.Length)
        {
            throw new ArgumentException("Payload buffer does not have enough space to hold the plaintext.");
        }

        if (this._turnToWrite)
        {
            throw new InvalidOperationException("Unexpected call to ReadMessage (should be WriteMessage).");
        }

        var next = this._messagePatterns.Dequeue();
        var messageLength = message.Length;

        foreach (var token in next.Tokens)
        {
            switch (token)
            {
                case Token.E:
                    message = this.ReadE(message);
                    break;
                case Token.S:
                    message = this.ReadS(message);
                    break;
                case Token.Ee:
                    this.DhAndMixKey(this._e, this._re ?? throw new InvalidOperationException("_re cannot be null"));
                    break;
                case Token.Es:
                    this.ProcessEs();
                    break;
                case Token.Se:
                    this.ProcessSe();
                    break;
                case Token.Ss:
                    this.DhAndMixKey(this._s, this._rs);
                    break;
                case Token.Psk:
                    this.ProcessPsk();
                    break;
            }
        }

        var bytesRead = this._state.DecryptAndHash(message, payloadBuffer);
        Debug.Assert(bytesRead == plaintextSize);

        Transport? transport = null;

        if (this._messagePatterns.Count == 0)
        {
            transport = this.Split();
        }

        this._turnToWrite = true;
        return (plaintextSize, transport);
    }

    private ReadOnlySpan<byte> ReadE(ReadOnlySpan<byte> buffer)
    {
        Debug.Assert(this._re == null);

        this._re = new X25519PublicKeyParameters(buffer.Slice(0, this._dh.DhLen).ToArray());
        this._state.MixHash(this._re.GetEncoded());

        if (this._isPsk)
        {
            this._state.MixKey(this._re.GetEncoded());
        }

        return buffer.Slice(this._re.GetEncoded().Length);
    }

    private ReadOnlySpan<byte> ReadS(ReadOnlySpan<byte> message)
    {
        Debug.Assert(this._rs == null);

        var length = this._state.HasKey() ? this._dh.DhLen + Aead.TagSize : this._dh.DhLen;
        var temp = message.Slice(0, length);

        var tempRs = new ByteArrayOwnership(this._dh.DhLen, "TempRsInReadS");
        this._state.DecryptAndHash(temp, tempRs.WriteAbleSpan);
        this._rs = new X25519PublicKeyParameters(tempRs.ReadOnlySpan);

        return message.Slice(length);
    }

    private void ProcessEs()
    {
        if (this._role == Role.Alice)
        {
            this.DhAndMixKey(this._e, this._rs);
        }
        else
        {
            this.DhAndMixKey(this._s, this._re ?? throw new InvalidOperationException("_re cannot be null!"));
        }
    }

    private void ProcessSe()
    {
        if (this._role == Role.Alice)
        {
            this.DhAndMixKey(this._s, this._re ?? throw new InvalidOperationException("_re cannot be null!"));
        }
        else
        {
            this.DhAndMixKey(this._e, this._rs);
        }
    }

    private void ProcessPsk()
    {
        var psk = this._psks.Dequeue();
        this._state.MixKeyAndHash(psk);
        Utilities.ZeroMemory(psk);
    }

    private Transport Split()
    {
        (var c1, var c2) = this._state.Split();

        if (this._isOneWay)
        {
            c2 = null;
        }

        Debug.Assert(this._psks.Count == 0);

        return new Transport(this._role == this._initiator, c1, c2);
    }

    private void DhAndMixKey(X25519KeyPair? keyPair, X25519PublicKeyParameters publicKey)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        Debug.Assert(keyPair != null);

        var sharedKey = new ByteArrayOwnership(this._dh.DhLen, "DhAndMixKey");
        try
        {
            this._dh.Dh(keyPair.Private, publicKey, sharedKey.WriteAbleSpan);
            this._state.MixKey(sharedKey.ReadOnlySpan);
        }
        finally
        {
            sharedKey.Dispose();
        }
    }

    private enum Role
    {
        Alice,
        Bob,
    }
}