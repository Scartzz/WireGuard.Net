using System.Diagnostics;
using Blake2Fast;
using WireGuard.Net.Noise.Statics;

namespace WireGuard.Net.Noise;

/// <summary>
///     A SymmetricState object contains a CipherState plus ck (a chaining
///     key of HashLen bytes) and h (a hash output of HashLen bytes).
/// </summary>
internal sealed class SymmetricState
{
    private readonly byte[] _ck;
    private readonly byte[] _h;
    private readonly Curve25519 _dh = new Curve25519();
    private readonly CipherState _state = new CipherState();

    /// <summary>
    ///     Initializes a new SymmetricState with an
    ///     arbitrary-length protocolName byte sequence.
    /// </summary>
    public SymmetricState(ReadOnlySpan<byte> protocolName)
    {
        const int length = 32;

        this._ck = new byte[length];
        this._h = new byte[length];

        if (protocolName.Length <= length)
        {
            protocolName.CopyTo(this._h);
        }
        else
        {
            var hash = Blake2s.CreateIncrementalHasher(32);
            hash.Update(protocolName);
            hash.Finish(this._h);
        }

        Array.Copy(this._h, this._ck, length);
    }

    /// <summary>
    ///     Sets ck, tempK = HKDF(ck, inputKeyMaterial, 2).
    ///     If HashLen is 64, then truncates tempK to 32 bytes.
    ///     Calls InitializeKey(tempK).
    /// </summary>
    public void MixKey(ReadOnlySpan<byte> inputKeyMaterial)
    {
        var length = inputKeyMaterial.Length;
        Debug.Assert(length == 0 || length == Aead.KeySize || length == this._dh.DhLen);

        const int hashLen = 32;

        Span<byte> output = stackalloc byte[2 * hashLen];
        Hkdf.ExtractAndExpand2(this._ck, inputKeyMaterial, output);

        output.Slice(0, hashLen).CopyTo(this._ck);

        var tempK = output.Slice(hashLen, Aead.KeySize);
        this._state.InitializeKey(tempK);
    }

    /// <summary>
    ///     Sets h = HASH(h || data).
    /// </summary>
    public void MixHash(ReadOnlySpan<byte> data)
    {
        var hash = Blake2s.CreateIncrementalHasher(32);
        hash.Update(this._h);
        hash.Update(data);
        hash.Finish(this._h);
    }

    /// <summary>
    ///     Sets ck, tempH, tempK = HKDF(ck, inputKeyMaterial, 3).
    ///     Calls MixHash(tempH).
    ///     If HashLen is 64, then truncates tempK to 32 bytes.
    ///     Calls InitializeKey(tempK).
    /// </summary>
    public void MixKeyAndHash(ReadOnlySpan<byte> inputKeyMaterial)
    {
        var length = inputKeyMaterial.Length;
        Debug.Assert(length == 0 || length == Aead.KeySize || length == this._dh.DhLen);

        const int hashLen = 32;

        Span<byte> output = stackalloc byte[3 * hashLen];
        Hkdf.ExtractAndExpand3(this._ck, inputKeyMaterial, output);

        output.Slice(0, hashLen).CopyTo(this._ck);

        var tempH = output.Slice(hashLen, hashLen);
        var tempK = output.Slice(2 * hashLen, Aead.KeySize);

        this.MixHash(tempH);
        this._state.InitializeKey(tempK);
    }

    /// <summary>
    ///     Sets ciphertext = EncryptWithAd(h, plaintext),
    ///     calls MixHash(ciphertext), and returns ciphertext.
    /// </summary>
    public int EncryptAndHash(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        var bytesWritten = this._state.EncryptWithAd(this._h, plaintext, ciphertext);
        this.MixHash(ciphertext.Slice(0, bytesWritten));

        return bytesWritten;
    }

    /// <summary>
    ///     Sets plaintext = DecryptWithAd(h, ciphertext),
    ///     calls MixHash(ciphertext), and returns plaintext.
    /// </summary>
    public int DecryptAndHash(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        var bytesRead = this._state.DecryptWithAd(this._h, ciphertext, plaintext);
        this.MixHash(ciphertext);

        return bytesRead;
    }

    /// <summary>
    ///     Returns a pair of CipherState objects for encrypting transport messages.
    /// </summary>
    public (CipherState c1, CipherState c2) Split()
    {
        return CipherState.Split(this._ck);
    }

    /// <summary>
    ///     Returns true if k is non-empty, false otherwise.
    /// </summary>
    public bool HasKey()
    {
        return this._state.HasKey();
    }
}