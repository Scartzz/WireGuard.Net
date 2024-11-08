using System.Diagnostics;
using Org.BouncyCastle.Crypto.Parameters;
using WireGuard.Net.Noise.Statics;

namespace WireGuard.Net.Noise;

/// <summary>
///     A CipherState can encrypt and decrypt data based on its variables k
///     (a cipher key of 32 bytes) and n (an 8-byte unsigned integer nonce).
/// </summary>
internal sealed class CipherState
{
    private const ulong MaxNonce = ulong.MaxValue;
    private byte[]? _key;
    private ulong _n;

    /// <summary>
    ///     Sets k = key. Sets n = 0.
    /// </summary>
    public void InitializeKey(ReadOnlySpan<byte> key)
    {
        Debug.Assert(key.Length == Aead.KeySize);

        this._key = this._key ?? new byte[Aead.KeySize];
        key.CopyTo(this._key);

        this._n = 0;
    }

    /// <summary>
    ///     Returns true if k is non-empty, false otherwise.
    /// </summary>
    public bool HasKey()
    {
        return this._key != null;
    }

    /// <summary>
    ///     If k is non-empty returns ENCRYPT(k, n++, ad, plaintext).
    ///     Otherwise copies the plaintext to the ciphertext parameter
    ///     and returns the length of the plaintext.
    /// </summary>
    public int EncryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        if (this._n == MaxNonce)
        {
            throw new OverflowException("Nonce has reached its maximum value.");
        }

        if (this._key == null)
        {
            plaintext.CopyTo(ciphertext);
            return plaintext.Length;
        }

        return CipherChaCha20Poly1305.Encrypt(new KeyParameter(this._key), this._n++, ad, plaintext, ciphertext);
    }

    /// <summary>
    ///     If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
    ///     Otherwise copies the ciphertext to the plaintext parameter and returns
    ///     the length of the ciphertext. If an authentication failure occurs
    ///     then n is not incremented and an error is signaled to the caller.
    /// </summary>
    public int DecryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        if (this._n == MaxNonce)
        {
            throw new OverflowException("Nonce has reached its maximum value.");
        }

        if (this._key == null)
        {
            ciphertext.CopyTo(plaintext);
            return ciphertext.Length;
        }

        var bytesRead = CipherChaCha20Poly1305.Decrypt(new KeyParameter(this._key), this._n, ad, ciphertext, plaintext);
        ++this._n;

        return bytesRead;
    }
    
    /// <summary>
    ///     Returns a pair of CipherState objects for encrypting transport messages.
    /// </summary>
    public static (CipherState c1, CipherState c2) Split(ReadOnlySpan<byte> chainingKey)
    {
        const int hashLen = 32;

        Span<byte> output = stackalloc byte[2 * hashLen];
        Hkdf.ExtractAndExpand2(chainingKey, null, output);

        var tempK1 = output.Slice(0, Aead.KeySize);
        var tempK2 = output.Slice(hashLen, Aead.KeySize);

        var c1 = new CipherState();
        var c2 = new CipherState();

        c1.InitializeKey(tempK1);
        c2.InitializeKey(tempK2);

        return (c1, c2);
    }
}