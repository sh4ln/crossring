using System;
using System.Windows;
using CrossringUI.Services;

namespace CrossringUI;

public partial class App : Application
{
    private PipeClient? _pipeClient;
    private NotificationService? _notificationService;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        
        // Initialize services
        _pipeClient = new PipeClient();
        _notificationService = new NotificationService();
        
        // Start pipe client
        _pipeClient.MessageReceived += OnMessageReceived;
        _pipeClient.ConnectAsync();
        
        // Handle unhandled exceptions
        DispatcherUnhandledException += (s, args) =>
        {
            MessageBox.Show($"An error occurred: {args.Exception.Message}", 
                "CROSSRING Error", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _pipeClient?.Dispose();
        base.OnExit(e);
    }

    private void OnMessageReceived(object? sender, PipeMessage message)
    {
        Dispatcher.Invoke(() =>
        {
            switch (message.Type)
            {
                case "process_blocked":
                    ShowAuthorizationPrompt(message);
                    break;
                case "anomaly":
                    _notificationService?.ShowAnomalyNotification(message);
                    break;
            }
        });
    }

    private void ShowAuthorizationPrompt(PipeMessage message)
    {
        var prompt = new Views.AuthPromptWindow(message);
        prompt.DecisionMade += (decision, scope) =>
        {
            _pipeClient?.SendDecision(message.EventId, decision, scope);
        };
        prompt.Show();
    }

    public static PipeClient? PipeClient => (Current as App)?._pipeClient;
}
