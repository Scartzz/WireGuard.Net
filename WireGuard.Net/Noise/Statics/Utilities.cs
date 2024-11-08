using System.Runtime.CompilerServices;

namespace WireGuard.Net.Noise.Statics;

/// <summary>
///     Various utility functions.
/// </summary>
internal static class Utilities
{
    // NoOptimize to prevent the optimizer from deciding this call is unnecessary.
    // NoInlining to prevent the inliner from forgetting that the method was NoOptimize.
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ZeroMemory(Span<byte> buffer)
    {
        buffer.Clear();
    }
}