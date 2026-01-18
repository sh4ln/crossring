using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace CrossringUI.Services;

public class PipeMessage
{
    public string Type { get; set; } = "";
    public ulong EventId { get; set; }
    public uint Pid { get; set; }
    public string ImagePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public string Hash { get; set; } = "";
    public bool Signed { get; set; }
    public string Signer { get; set; } = "";
    public string Timestamp { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string AnomalyType { get; set; } = "";
    public ulong RegionSize { get; set; }
}

public class PipeClient : IDisposable
{
    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _cts;
    private Task? _readTask;
    private bool _disposed;
    
    // HMAC key for message authentication
    private byte[]? _hmacKey;

    public event EventHandler<PipeMessage>? MessageReceived;
    public event Action? Connected;
    public event Action? Disconnected;

    public PipeClient()
    {
        LoadHmacKey();
    }

    private void LoadHmacKey()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\CROSSRING\IPC");
            if (key != null)
            {
                _hmacKey = key.GetValue("Secret") as byte[];
            }
        }
        catch
        {
            _hmacKey = null;
        }
    }

    private string ComputeHmac(string data)
    {
        if (_hmacKey == null || _hmacKey.Length != 32)
        {
            return "";
        }

        using var hmac = new HMACSHA256(_hmacKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return BitConverter.ToString(hash).Replace("-", "").ToLower();
    }

    public async void ConnectAsync()
    {
        _cts = new CancellationTokenSource();
        
        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                _pipe = new NamedPipeClientStream(".", "CrossringPipe", 
                    PipeDirection.InOut, PipeOptions.Asynchronous);
                
                await _pipe.ConnectAsync(5000, _cts.Token);
                Connected?.Invoke();
                
                _readTask = ReadLoop(_cts.Token);
                await _readTask;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                Disconnected?.Invoke();
                await Task.Delay(2000, _cts.Token);
            }
            finally
            {
                _pipe?.Dispose();
                _pipe = null;
            }
        }
    }

    private async Task ReadLoop(CancellationToken ct)
    {
        if (_pipe == null) return;
        
        var lengthBuffer = new byte[4];
        
        while (!ct.IsCancellationRequested && _pipe.IsConnected)
        {
            try
            {
                int bytesRead = await _pipe.ReadAsync(lengthBuffer.AsMemory(0, 4), ct);
                if (bytesRead < 4) break;
                
                uint length = BitConverter.ToUInt32(lengthBuffer, 0);
                if (length > 65536) continue;
                
                var messageBuffer = new byte[length];
                bytesRead = await _pipe.ReadAsync(messageBuffer.AsMemory(0, (int)length), ct);
                if (bytesRead < length) break;
                
                var json = Encoding.UTF8.GetString(messageBuffer);
                var message = JsonSerializer.Deserialize<PipeMessage>(json, 
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                
                if (message != null)
                {
                    MessageReceived?.Invoke(this, message);
                }
            }
            catch
            {
                break;
            }
        }
        
        Disconnected?.Invoke();
    }

    public void SendDecision(ulong eventId, string action, string scope)
    {
        if (_pipe == null || !_pipe.IsConnected) return;
        
        // Create message without HMAC first
        var messageData = new
        {
            type = "decision",
            event_id = eventId,
            action,
            scope,
            timestamp = DateTime.UtcNow.ToString("o")
        };
        
        // Serialize to compute HMAC
        var payloadJson = JsonSerializer.Serialize(messageData);
        var hmac = ComputeHmac(payloadJson);
        
        // Create final message with HMAC
        var authenticatedMessage = new
        {
            type = "decision",
            event_id = eventId,
            action,
            scope,
            timestamp = messageData.timestamp,
            hmac
        };
        
        var json = JsonSerializer.Serialize(authenticatedMessage);
        var bytes = Encoding.UTF8.GetBytes(json);
        var lengthBytes = BitConverter.GetBytes((uint)bytes.Length);
        
        try
        {
            _pipe.Write(lengthBytes, 0, 4);
            _pipe.Write(bytes, 0, bytes.Length);
            _pipe.Flush();
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        
        _cts?.Cancel();
        _pipe?.Dispose();
        _cts?.Dispose();
    }
}
