using System;
using System.Windows;

namespace CrossringUI.Services;

public class NotificationService
{
    public void ShowAnomalyNotification(PipeMessage message)
    {
        Application.Current?.Dispatcher?.Invoke(() =>
        {
            MessageBox.Show(
                $"Memory anomaly detected!\n\nProcess: {message.ProcessName}\nPID: {message.Pid}\nType: {message.AnomalyType}",
                "CROSSRING Alert",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        });
    }

    public void ShowProcessBlockedNotification(PipeMessage message)
    {
        Application.Current?.Dispatcher?.Invoke(() =>
        {
            var fileName = System.IO.Path.GetFileName(message.ImagePath ?? "Unknown");
            MessageBox.Show(
                $"Execution blocked!\n\nFile: {fileName}\nPath: {message.ImagePath}\n\nOpen CROSSRING to review and authorize.",
                "CROSSRING - Execution Blocked",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        });
    }

    public void ShowSecurityAlert(string title, string message)
    {
        Application.Current?.Dispatcher?.Invoke(() =>
        {
            MessageBox.Show(message, $"CROSSRING - {title}", MessageBoxButton.OK, MessageBoxImage.Warning);
        });
    }
}
