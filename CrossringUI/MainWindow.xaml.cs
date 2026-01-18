using System.Windows;
using CrossringUI.ViewModels;

namespace CrossringUI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
        
        // Minimize to tray on close
        Closing += (s, e) =>
        {
            e.Cancel = true;
            Hide();
        };
    }
}
