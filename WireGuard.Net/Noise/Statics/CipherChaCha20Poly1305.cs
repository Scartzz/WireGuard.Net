using System.Buffers.Binary;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace WireGuard.Net.Noise.Statics;

/// <summary>
///     AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
///     The 96-bit nonce is formed by encoding 32 bits
///     of zeros followed by little-endian encoding of n.
/// </summary>
internal static class CipherChaCha20Poly1305
{
    private static byte[] GetNonce(ulong n)
    {
        var nonce = new byte[Aead.NonceSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan()[4..], n);
        return nonce;
    }

    private static ICipherParameters GetParameters(KeyParameter key, ulong nonce, ReadOnlySpan<byte> additionalData)
    {
        return new AeadParameters(key, 16 * 8, GetNonce(nonce), additionalData.ToArray());
    }

    private static ChaCha20Poly1305 GetCipher(bool forEncryption, ICipherParameters cipherParameters)
    {
        var cipher = new ChaCha20Poly1305();
        cipher.Init(forEncryption, cipherParameters);
        return cipher;
    }

    private static void ProcessCipher(ChaCha20Poly1305 cipher, ReadOnlySpan<byte> from, Span<byte> to, int expectedSize)
    {
        var outputSize = cipher.GetOutputSize(from.Length);

        if (outputSize != expectedSize)
            throw new InvalidOperationException($"Expected Output in {expectedSize} but calculated {outputSize}");
        if (to.Length < outputSize)
            throw new InvalidOperationException($"Expected Output in {outputSize} but only got {to.Length}");

        var temp = new byte[outputSize];
        var result = cipher.ProcessBytes(from.ToArray(), 0, from.Length, temp, 0);
        cipher.DoFinal(temp, result);

        temp.AsSpan(0, outputSize).CopyTo(to);
    }

    public static int Encrypt(KeyParameter key, ulong nonce, ReadOnlySpan<byte> additionalData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        Debug.Assert(ciphertext.Length >= plaintext.Length + Aead.TagSize);

        var expectedSize = plaintext.Length + Aead.TagSize;
        ProcessCipher(GetCipher(true, GetParameters(key, nonce, additionalData)), plaintext, ciphertext, expectedSize);
        return expectedSize;
    }

    public static int Decrypt(KeyParameter key, ulong nonce, ReadOnlySpan<byte> additionalData, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Debug.Assert(ciphertext.Length >= Aead.TagSize);
        Debug.Assert(plaintext.Length >= ciphertext.Length - Aead.TagSize);

        var expectedSize = ciphertext.Length - Aead.TagSize;
        ProcessCipher(GetCipher(false, GetParameters(key, nonce, additionalData)), ciphertext, plaintext, expectedSize);
        return expectedSize;
    }
}