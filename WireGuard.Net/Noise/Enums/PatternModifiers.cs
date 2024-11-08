namespace WireGuard.Net.Noise.Enums;

/// <summary>
///     Pattern modifiers specify arbitrary extensions or modifications
///     to the behavior specified by the handshake pattern.
/// </summary>
[Flags]
internal enum PatternModifiers
{
	/// <summary>
	///     No pattern modifiers were selected.
	/// </summary>
	None = 0,

	/// <summary>
	///     The modifier psk0 places a "psk" token at
	///     the beginning of the first handshake message.
	/// </summary>
	Psk0 = 2,

	/// <summary>
	///     The modifier psk1 places a "psk" token at
	///     the end of the first handshake message.
	/// </summary>
	Psk1 = 4,

	/// <summary>
	///     The modifier psk2 places a "psk" token at
	///     the end of the second handshake message.
	/// </summary>
	Psk2 = 8,

	/// <summary>
	///     The modifier psk0 places a "psk" token at
	///     the end of the third handshake message.
	/// </summary>
	Psk3 = 16,
}