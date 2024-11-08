using Org.BouncyCastle.Crypto.Parameters;

namespace WireGuard.Net;

public class X25519KeyPair
{
    public X25519KeyPair(byte[] privateKey)
    {
        this.Private = new X25519PrivateKeyParameters(privateKey);
        this.Public = this.Private.GeneratePublicKey();
    }

    public X25519KeyPair(X25519PublicKeyParameters publicKey, X25519PrivateKeyParameters privateKey)
    {
        this.Public = publicKey;
        this.Private = privateKey;
    }

    public X25519PublicKeyParameters Public { get; }
    public X25519PrivateKeyParameters Private { get; }
}