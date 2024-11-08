using Org.BouncyCastle.Crypto.Parameters;

namespace WireGuard.Net;

public class WireGuardSettings
{
    public WireGuardSettings(X25519KeyPair localKeyPair, string serverPublicKey, string serverIp, string serverVirtualIp, int serverPort, string localIp)
    {
        this.LocalKeyPair = localKeyPair;
        this.ServerKey = new X25519PublicKeyParameters(Convert.FromBase64String(serverPublicKey));
        this.ServerIp = serverIp;
        this.ServerVirtualIp = serverVirtualIp;
        this.ServerPort = serverPort;
        this.LocalIp = localIp;
    }
    
    public X25519KeyPair LocalKeyPair { get; }
    public X25519PublicKeyParameters ServerKey { get; }
    public string ServerIp { get; }
    public string ServerVirtualIp { get; }
    public int ServerPort { get; }
    public string LocalIp { get; }
}