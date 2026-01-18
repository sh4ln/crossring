using System.Windows;

namespace CrossringUI.Views;

public partial class FirstRunDialog : Window
{
    public enum ProtectionMode
    {
        Monitoring,
        Balanced,
        ZeroTrust
    }
    
    public ProtectionMode SelectedMode { get; private set; } = ProtectionMode.Balanced;
    
    public FirstRunDialog()
    {
        InitializeComponent();
    }
    
    private void OnStartClicked(object sender, RoutedEventArgs e)
    {
        if (RbMonitoring.IsChecked == true)
            SelectedMode = ProtectionMode.Monitoring;
        else if (RbZeroTrust.IsChecked == true)
            SelectedMode = ProtectionMode.ZeroTrust;
        else
            SelectedMode = ProtectionMode.Balanced;
        
        DialogResult = true;
        Close();
    }
}
