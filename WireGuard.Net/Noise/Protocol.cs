namespace WireGuard.Net.Noise;

/// <summary>
///     A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_SHA256 or Noise_IK_25519_ChaChaPoly_BLAKE2b).
/// </summary>
internal static class Protocol
{
	/// <summary>
	///     Maximum size of the Noise protocol message in bytes.
	/// </summary>
	public const int MaxMessageLength = 65535;
}