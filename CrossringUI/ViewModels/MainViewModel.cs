using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CrossringUI.Models;
using CrossringUI.Services;

namespace CrossringUI.ViewModels;

public partial class MainViewModel : ObservableObject
{
    [ObservableProperty] private string _connectionStatus = "Connecting...";
    [ObservableProperty] private Brush _statusColor = Brushes.Yellow;
    [ObservableProperty] private string _statusMessage = "Initializing...";
    [ObservableProperty] private int _totalEvents;
    [ObservableProperty] private int _totalAnomalies;
    
    public ObservableCollection<ProcessEventModel> ProcessEvents { get; } = new();
    public ObservableCollection<MemoryAnomalyModel> Anomalies { get; } = new();
    public ObservableCollection<WhitelistEntryModel> WhitelistEntries { get; } = new();

    public MainViewModel()
    {
        var pipeClient = App.PipeClient;
        if (pipeClient != null)
        {
            pipeClient.Connected += () => Application.Current.Dispatcher.Invoke(() =>
            {
                ConnectionStatus = "Connected";
                StatusColor = Brushes.LimeGreen;
                StatusMessage = "Service connected - Monitoring active";
            });
            
            pipeClient.Disconnected += () => Application.Current.Dispatcher.Invoke(() =>
            {
                ConnectionStatus = "Disconnected";
                StatusColor = Brushes.Red;
                StatusMessage = "Service disconnected - Reconnecting...";
            });
            
            pipeClient.MessageReceived += (s, msg) => Application.Current.Dispatcher.Invoke(() =>
            {
                if (msg.Type == "process_blocked")
                {
                    ProcessEvents.Insert(0, new ProcessEventModel
                    {
                        Timestamp = msg.Timestamp,
                        Pid = msg.Pid,
                        ProcessName = System.IO.Path.GetFileName(msg.ImagePath),
                        ImagePath = msg.ImagePath,
                        Decision = "Pending"
                    });
                    TotalEvents = ProcessEvents.Count;
                }
                else if (msg.Type == "anomaly")
                {
                    Anomalies.Insert(0, new MemoryAnomalyModel
                    {
                        Timestamp = msg.Timestamp,
                        Pid = msg.Pid,
                        ProcessName = msg.ProcessName,
                        AnomalyType = msg.AnomalyType,
                        RegionSize = msg.RegionSize
                    });
                    TotalAnomalies = Anomalies.Count;
                }
            });
        }
        
        LoadDatabaseData();
    }

    private void LoadDatabaseData()
    {
        var dbService = new DatabaseService();
        foreach (var entry in dbService.GetWhitelistEntries())
        {
            WhitelistEntries.Add(entry);
        }
    }

    [RelayCommand]
    private void ShowWindow()
    {
        Application.Current.MainWindow?.Show();
        Application.Current.MainWindow?.Activate();
    }

    [RelayCommand]
    private void OpenSettings()
    {
        // TODO: Open settings window
    }

    [RelayCommand]
    private void Exit()
    {
        Application.Current.Shutdown();
    }

    [RelayCommand]
    private void AddWhitelist()
    {
        // TODO: Show add whitelist dialog
    }

    [RelayCommand]
    private void RemoveWhitelist()
    {
        // TODO: Remove selected whitelist entry
    }
}
