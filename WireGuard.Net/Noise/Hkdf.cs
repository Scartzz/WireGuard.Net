using System.Diagnostics;
using Blake2Fast;

namespace WireGuard.Net.Noise;

/// <summary>
///     HMAC-based Extract-and-Expand Key Derivation Function, defined in
///     <see href="https://tools.ietf.org/html/rfc5869">RFC 5869</see>.
/// </summary>
internal static class Hkdf
{
    private static readonly byte[] One = { 1 };
    private static readonly byte[] Two = { 2 };
    private static readonly byte[] Three = { 3 };

    /// <summary>
    ///     Takes a chainingKey byte sequence of length HashLen,
    ///     and an inputKeyMaterial byte sequence with length
    ///     either zero bytes, 32 bytes, or DhLen bytes. Writes a
    ///     byte sequences of length 2 * HashLen into output parameter.
    /// </summary>
    public static void ExtractAndExpand2(
        ReadOnlySpan<byte> chainingKey,
        ReadOnlySpan<byte> inputKeyMaterial,
        Span<byte> output)
    {
        const int hashLen = 32;

        Debug.Assert(chainingKey.Length == hashLen);
        Debug.Assert(output.Length == 2 * hashLen);

        Span<byte> tempKey = stackalloc byte[hashLen];
        Hkdf.HmacHash(chainingKey, tempKey, inputKeyMaterial);

        var output1 = output.Slice(0, hashLen);
        Hkdf.HmacHash(tempKey, output1, One);

        var output2 = output.Slice(hashLen, hashLen);
        Hkdf.HmacHash(tempKey, output2, output1, Two);
    }

    /// <summary>
    ///     Takes a chainingKey byte sequence of length HashLen,
    ///     and an inputKeyMaterial byte sequence with length
    ///     either zero bytes, 32 bytes, or DhLen bytes. Writes a
    ///     byte sequences of length 3 * HashLen into output parameter.
    /// </summary>
    public static void ExtractAndExpand3(
        ReadOnlySpan<byte> chainingKey,
        ReadOnlySpan<byte> inputKeyMaterial,
        Span<byte> output)
    {
        const int hashLen = 32;

        Debug.Assert(chainingKey.Length == hashLen);
        Debug.Assert(output.Length == 3 * hashLen);

        Span<byte> tempKey = stackalloc byte[hashLen];
        Hkdf.HmacHash(chainingKey, tempKey, inputKeyMaterial);

        var output1 = output.Slice(0, hashLen);
        Hkdf.HmacHash(tempKey, output1, One);

        var output2 = output.Slice(hashLen, hashLen);
        Hkdf.HmacHash(tempKey, output2, output1, Two);

        var output3 = output.Slice(2 * hashLen, hashLen);
        Hkdf.HmacHash(tempKey, output3, output2, Three);
    }

    private static void HmacHash(
        ReadOnlySpan<byte> key,
        Span<byte> hmac,
        ReadOnlySpan<byte> data1 = default,
        ReadOnlySpan<byte> data2 = default)
    {
        Debug.Assert(key.Length == 32);
        Debug.Assert(hmac.Length == 32);

        const int hashBlockLen = 64;

        Span<byte> ipad = stackalloc byte[hashBlockLen];
        Span<byte> opad = stackalloc byte[hashBlockLen];

        key.CopyTo(ipad);
        key.CopyTo(opad);

        for (var i = 0; i < hashBlockLen; ++i)
        {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5C;
        }

        var inner = Blake2s.CreateIncrementalHasher(32);

        inner.Update(ipad);
        inner.Update(data1);
        inner.Update(data2);
        inner.Finish(hmac);

        var outer = Blake2s.CreateIncrementalHasher(32);

        outer.Update(opad);
        outer.Update(hmac);
        outer.Finish(hmac);
    }
}