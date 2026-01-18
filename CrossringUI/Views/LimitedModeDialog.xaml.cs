using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;

namespace CrossringUI.Views;

public partial class LimitedModeDialog : Window
{
    public bool DontShowAgain { get; private set; }
    
    public LimitedModeDialog()
    {
        InitializeComponent();
    }
    
    private void OnContinue(object sender, RoutedEventArgs e)
    {
        DontShowAgain = ChkDontShowAgain.IsChecked == true;
        DialogResult = true;
        Close();
    }
    
    private void OnRestartElevated(object sender, RoutedEventArgs e)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                UseShellExecute = true,
                WorkingDirectory = Environment.CurrentDirectory,
                FileName = Process.GetCurrentProcess().MainModule!.FileName,
                Verb = "runas"  // Trigger UAC
            };
            
            Process.Start(startInfo);
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to restart elevated: {ex.Message}", 
                          "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    public static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
