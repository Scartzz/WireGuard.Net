using System.Diagnostics;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace WireGuard.Net.Noise;

/// <summary>
///     The Curve25519 DH function (aka "X25519" in
///     <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>).
/// </summary>
internal sealed class Curve25519
{
    public int DhLen => 32;

    public X25519KeyPair GenerateKeyPair()
    {
        var secureRandom = new SecureRandom();
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(secureRandom);
        X25519PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
        return new X25519KeyPair(publicKey, privateKey);
    }

    public void Dh(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey, Span<byte> sharedKey)
    {
        Debug.Assert(sharedKey.Length == this.DhLen);

        privateKey.GenerateSecret(publicKey, sharedKey);
    }
}