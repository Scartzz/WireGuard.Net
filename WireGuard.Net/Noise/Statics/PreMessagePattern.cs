using WireGuard.Net.Noise.Enums;

namespace WireGuard.Net.Noise.Statics;

/// <summary>
///     A pre-message pattern is one of the following
///     sequences of tokens: "e", "s", "e, s", or empty.
/// </summary>
internal sealed class PreMessagePattern
{
	/// <summary>
	///     The "s" pre-message pattern.
	/// </summary>
	public static readonly PreMessagePattern S = new PreMessagePattern(Token.S);

	/// <summary>
	///     The empty pre-message pattern.
	/// </summary>
	public static readonly PreMessagePattern Empty = new PreMessagePattern();

    private PreMessagePattern(params Token[] tokens)
    {
        this.Tokens = tokens;
    }

    /// <summary>
    ///     Gets the tokens of the pre-message pattern.
    /// </summary>
    public IEnumerable<Token> Tokens { get; }
}