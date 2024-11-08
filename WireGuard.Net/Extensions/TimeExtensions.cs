namespace WireGuard.Net.Extensions;

internal static class TimeExtensions
{
    internal static bool IsLaterThan(this DateTimeOffset dateTime, TimeSpan timeSpan)
    {
        return DateTimeOffset.UtcNow - dateTime > timeSpan;
    }
}