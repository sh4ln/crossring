using System.Windows;

namespace CrossringUI.Views;

public partial class SettingsWindow : Window
{
    public SettingsWindow()
    {
        InitializeComponent();
        LoadSettings();
    }

    private void LoadSettings()
    {
        // TODO: Load from config file
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        // TODO: Save settings to config file
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
