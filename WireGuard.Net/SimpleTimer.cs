using System.Timers;
using Timer = System.Timers.Timer;

namespace WireGuard.Net;

public class SimpleTimer : IDisposable
{
    private readonly CancellationTokenSource _cts;
    private readonly Func<CancellationToken, Task> _func;
    private readonly Timer _timer;
    private bool _disposed;

    public SimpleTimer(int interval, Func<CancellationToken, Task> func)
    {
        this._func = func;
        this._cts = new CancellationTokenSource();
        this._disposed = false;
        this._timer = new Timer(interval);
        this._timer.AutoReset = false;
        this._timer.Elapsed += this.OnTimedEvent;
        this._timer.Start();
    }

    ~SimpleTimer()
    {
        this._disposed = true;
        this._cts.Cancel();
        this._timer.Stop();
        this._timer.Dispose();
    }

    private async void OnTimedEvent(object? sender, ElapsedEventArgs e)
    {
        try
        {
            await this._func(this._cts.Token).ConfigureAwait(false);
        }
        catch (Exception exc)
        {
            if (!this._cts.IsCancellationRequested)
            {
                await Console.Error.WriteLineAsync(exc.ToString()).ConfigureAwait(false);
            }
        }
        if (!this._cts.IsCancellationRequested)
        {
            this._timer.Start();
        }
    }

    public void Dispose()
    {
        if (this._disposed)
            return;
        this._disposed = true;
        this._cts.Cancel();
        this._timer.Stop();
        this._timer.Dispose();
    }
}