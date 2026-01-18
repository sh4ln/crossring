using System;
using System.IO;
using System.Windows;
using System.Windows.Media;
using CrossringUI.Services;

namespace CrossringUI.Views;

public partial class AuthPromptWindow : Window
{
    private readonly PipeMessage _message;
    public event Action<string, string>? DecisionMade;

    public AuthPromptWindow(PipeMessage message)
    {
        InitializeComponent();
        _message = message;
        
        // Populate UI
        TxtProcessName.Text = Path.GetFileName(message.ImagePath);
        TxtPath.Text = message.ImagePath;
        TxtHash.Text = message.Hash;
        
        if (message.Signed)
        {
            SignedIndicator.Fill = new SolidColorBrush(Color.FromRgb(74, 222, 128));
            TxtSigner.Text = string.IsNullOrEmpty(message.Signer) ? "Signed" : message.Signer;
        }
        else
        {
            SignedIndicator.Fill = new SolidColorBrush(Color.FromRgb(239, 68, 68));
            TxtSigner.Text = "Not signed";
        }
    }

    private void Deny_Click(object sender, RoutedEventArgs e)
    {
        DecisionMade?.Invoke("deny", "once");
        Close();
    }

    private void AllowOnce_Click(object sender, RoutedEventArgs e)
    {
        DecisionMade?.Invoke("allow", "once");
        Close();
    }

    private void AllowSession_Click(object sender, RoutedEventArgs e)
    {
        DecisionMade?.Invoke("allow", "session");
        Close();
    }

    private void AllowPermanent_Click(object sender, RoutedEventArgs e)
    {
        DecisionMade?.Invoke("allow", "permanent");
        Close();
    }
}
