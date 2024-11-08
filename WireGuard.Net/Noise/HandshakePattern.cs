using System.Diagnostics;
using WireGuard.Net.Noise.Enums;
using WireGuard.Net.Noise.Statics;

namespace WireGuard.Net.Noise;

/// <summary>
///     A <see href="https://noiseprotocol.org/noise.html#handshake-patterns">handshake pattern</see>
///     consists of a pre-message pattern for the initiator, a pre-message pattern for the responder,
///     and a sequence of message patterns for the actual handshake messages.
/// </summary>
internal sealed class HandshakePattern
{
	/// <summary>
	///     IK():
	///     <para>- ← s</para>
	///     <para>- ...</para>
	///     <para>- → e, es, s, ss</para>
	///     <para>- ← e, ee, se</para>
	/// </summary>
	public static readonly HandshakePattern Ik = new HandshakePattern(
        PreMessagePattern.Empty,
        PreMessagePattern.S,
        new MessagePattern(Token.E, Token.Es, Token.S, Token.Ss),
        new MessagePattern(Token.E, Token.Ee, Token.Se)
    );

    internal HandshakePattern(PreMessagePattern initiator, PreMessagePattern responder, params MessagePattern[] patterns)
    {
        Debug.Assert(initiator != null);
        Debug.Assert(responder != null);
        Debug.Assert(patterns != null);
        Debug.Assert(patterns.Length > 0);

        this.Initiator = initiator;
        this.Responder = responder;
        this.Patterns = patterns;
    }

    /// <summary>
    ///     Gets the pre-message pattern for the initiator.
    /// </summary>
    public PreMessagePattern Initiator { get; }

    /// <summary>
    ///     Gets the pre-message pattern for the responder.
    /// </summary>
    public PreMessagePattern Responder { get; }

    /// <summary>
    ///     Gets the sequence of message patterns for the handshake messages.
    /// </summary>
    public IEnumerable<MessagePattern> Patterns { get; }
}