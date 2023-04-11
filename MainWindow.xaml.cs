// This code is licensed under the GNU General Public License (GPL).
// For more information, see the LICENSE file.
using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Windows;
using System.Text.RegularExpressions;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using System.Windows.Data;
using System.Text;
using Microsoft.Win32;
using System.Linq;

namespace PacketCapture
{
    
    public partial class MainWindow : Window
    {
        public static bool IsDarkThemeEnabled()
        {
            const string keyName = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
            const string valueName = "SystemUsesLightTheme";

            int value = (int)Registry.GetValue(keyName, valueName, 2);

            return value == 0;
        }
        public ObservableCollection<int> FilteredPorts { get; set; } = new ObservableCollection<int>();
        private readonly StringBuilder _pktMonProcessOutputBuilder = new StringBuilder();
        private bool IsCapturing = false;
        private ObservableCollection<OutputData> _outputData = new ObservableCollection<OutputData>();
        private readonly Regex outputLineRegex = new Regex(@"(?<source>[A-Fa-f0-9\-]+) > (?<destination>[A-Fa-f0-9\-]+), ethertype (?<ethertype>\w+) \((?<etypecode>0x[A-Fa-f0-9]+)\), length (?<length>\d+): (?<info>.+)");
        private Process _pktMonProcess;
        private Process _pktMonStopProcess;
        private readonly DispatcherTimer _updateTimer;
        private bool _processExited = false;
        public MainWindow()
        {
            InitializeComponent();
            ToggleTheme();
            _outputData = new ObservableCollection<OutputData>();
            OutputDataGrid.ItemsSource = _outputData;
            System.Windows.Data.CollectionViewSource outputDataViewSource = (CollectionViewSource)FindResource("outputDataViewSource");
            outputDataViewSource.Source = _outputData;

            _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _updateTimer.Tick += UpdateTimer_Tick;
            _updateTimer.Start();
            Closing += MainWindow_Closing;
        }
        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            IsCapturing = false;
            StopCapture();
        }
        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            IsCapturing = true;
            StopButton.IsEnabled = true;
            StartButton.IsEnabled = false;
            StartCapture();
        }
        private void ToggleTheme()
        {
            if (SystemParameters.HighContrast)
            {
                // If high contrast is enabled, use the default system theme
                Resources.MergedDictionaries.Clear();
            }
            else if (IsDarkThemeEnabled())
            {
                // If dark mode is enabled, switch to the DarkTheme
                Resources.MergedDictionaries.Clear();
                Resources.MergedDictionaries.Add(new ResourceDictionary() { Source = new Uri("DarkTheme.xaml", UriKind.Relative) });
            }
            else
            {
                // Otherwise, use the LightTheme
                Resources.MergedDictionaries.Clear();
                Resources.MergedDictionaries.Add(new ResourceDictionary() { Source = new Uri("LightTheme.xaml", UriKind.Relative) });
            }
        }
        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            StopButton.IsEnabled = false;
            StartButton.IsEnabled = true;
            IsCapturing = false;
            StopCapture();
        }

        private void StartCapture()
        {
            var clearFilterProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/C pktmon filter remove",
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            clearFilterProcess.Start();
            clearFilterProcess.WaitForExit();
            if (FilterPorts.Items.Count > 0)
            {
                // Add port filters
                foreach (int port in FilterPorts.Items)
                {
                    var addFilterProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/C pktmon filter add -p {port}",
                            RedirectStandardOutput = true,
                            RedirectStandardInput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    addFilterProcess.Start();
                    addFilterProcess.WaitForExit();
                }
            }
            if (FilterIPs.Items.Count > 0)
            {
                // Add port filters
                foreach (string IP in FilterIPs.Items)
                {
                    var addFilterProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/C pktmon filter add -i {IP}",
                            RedirectStandardOutput = true,
                            RedirectStandardInput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    addFilterProcess.Start();
                    addFilterProcess.WaitForExit();
                }
            }
            // Clear output data and start packet capture
            _outputData.Clear();
            _pktMonProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/C pktmon start --etw --log-mode real-time",
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            _pktMonProcess.OutputDataReceived += PktMonProcess_OutputDataReceived;
            _pktMonProcess.Start();
            _pktMonProcess.BeginOutputReadLine();
        }

        private void PktMonProcess_Exited(object sender, EventArgs e)
        {
            Debug.WriteLine("Process exited");
            _processExited = true;
        }
        private void StopCapture()
        {
            _pktMonStopProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/C pktmon stop",
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            _pktMonStopProcess.Start();
            _pktMonStopProcess.Dispose();
            if (_pktMonProcess != null && !_pktMonProcess.HasExited)
            {
                _pktMonProcess.Exited -= PktMonProcess_Exited;

                try
                {
                    _pktMonProcess.Kill();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error stopping packet capture process: {ex.Message}");
                }
            }
            _processExited = true;       
            _updateTimer.Stop();
                      
        }
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Set up the data source for the data grid
            var outputData = new ObservableCollection<OutputData>();
            OutputDataGrid.ItemsSource = outputData;
            CollectionViewSource.GetDefaultView(outputData).Refresh();

            // Subscribe to the CollectionChanged event of the data source
            ((INotifyCollectionChanged)outputData).CollectionChanged += OutputData_CollectionChanged;
        }

        private void OutputData_CollectionChanged(object sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
        {
            if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Add)
            {
                OutputDataGrid.ScrollIntoView(OutputDataGrid.Items[OutputDataGrid.Items.Count - 1]);
                OutputDataGrid.SelectedItem = OutputDataGrid.Items[OutputDataGrid.Items.Count - 1];
                OutputDataGrid.Focus();
            }
        }


        private void PktMonProcess_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (!IsCapturing) return; // stop processing output if not capturing
            if (e.Data == null)
            {
                _pktMonProcess.Exited -= PktMonProcess_Exited;
                return;
            }
            Debug.WriteLine("Received data: " + e.Data);

            var match = outputLineRegex.Match(e.Data);
            if (match.Success)
            {
                Debug.WriteLine("Matched groups: " + string.Join(", ", match.Groups));
                var outputData = new OutputData
                {
                    Timestamp = DateTime.Now,
                    Source = match.Groups["source"].Value,
                    Destination = match.Groups["destination"].Value,
                    Ethertype = match.Groups["ethertype"].Value,
                    Length = match.Groups["length"].Value,
                    Info = match.Groups["info"].Value
                };

                Dispatcher.Invoke(() =>
                {
                    _outputData.Add(outputData);
                    Debug.WriteLine("Added to _outputData");
                });
            }        
            _pktMonProcess.Exited += PktMonProcess_Exited;
        }

        private void FilterTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            ApplyFilter();
        }
        private void ApplyFilter()
        {
            var filteredData = _outputData
                .Where(data => string.IsNullOrEmpty(FilterTextBox.Text) || data.Info.Contains(FilterTextBox.Text, StringComparison.OrdinalIgnoreCase))
                .ToList();

            OutputDataGrid.ItemsSource = filteredData;

            Debug.WriteLine("Items in ItemsSource: " + OutputDataGrid.Items.Count);
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            if (_pktMonProcess != null && !_pktMonProcess.HasExited)
            {
                var data = _pktMonProcessOutputBuilder.ToString();

                if (!string.IsNullOrWhiteSpace(data))
                {
                    _pktMonProcessOutputBuilder.Clear();
                    Debug.WriteLine(data);

                    // Create a new OutputData object
                    var outputData = new OutputData();

                    var match = outputLineRegex.Match(data);
                    if (match.Success)
                    {
                        Debug.WriteLine("Matched groups: " + string.Join(", ", match.Groups));

                        outputData.Source = match.Groups["source"].Value;
                        outputData.Destination = match.Groups["destination"].Value;
                        outputData.Ethertype = match.Groups["ethertype"].Value;
                        outputData.Length = match.Groups["length"].Value;
                        outputData.Info = match.Groups["info"].Value;

                        // Add the object to the collection if it matches the filter or if there is no filter
                        if (string.IsNullOrWhiteSpace(FilterTextBox.Text) || outputData.Info.Contains(FilterTextBox.Text))
                        {
                            _outputData.Add(outputData);
                        }
                    }
                }
            }
            else
            {
                if (!_processExited)
                {
                    _processExited = true;
                    StartButton.IsEnabled = true;
                    StopButton.IsEnabled = false;
                    _updateTimer.Stop();
                }
            }
        }
        private void AddPortButton_Click(object sender, RoutedEventArgs e)
        {
            int port;
            if (int.TryParse(PortTextBox.Text, out port))
            {
                FilterPorts.Items.Add(port);
                PortTextBox.Text = "";
            }
            else
            {
                MessageBox.Show("Invalid port number. Please enter an integer.");
            }
        }
        private void RemovePortButton_Click(object sender, RoutedEventArgs e)
        {
            if (FilterPorts.SelectedItem != null)
            {
                FilterPorts.Items.Remove(FilterPorts.SelectedItem);
            }
        }

        private void AddIpButton_Click(object sender, RoutedEventArgs e)
        {
            string ipAddress = IPTextBox.Text.Trim();

            // Regular expression to match a valid IPv4 address
            string ipv4Pattern = @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            if (Regex.IsMatch(ipAddress, ipv4Pattern))
            {
                FilterIPs.Items.Add(ipAddress);
                IPTextBox.Text = string.Empty;
            }
            else
            {
                MessageBox.Show("Invalid IP address format.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RemoveIpButton_Click(object sender, RoutedEventArgs e)
        {
            if (FilterIPs.SelectedItem != null)
            {
                FilterIPs.Items.Remove(FilterIPs.SelectedItem);
            }
        }
    }

    public class OutputData : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        private DateTime _timestamp;
        public DateTime Timestamp
        {
            get { return _timestamp; }
            set { _timestamp = value; OnPropertyChanged(); }
        }
        private string _source;
        public string Source
        {
            get { return _source; }
            set { _source = value; OnPropertyChanged(); }
        }

        private string _destination;
        public string Destination
        {
            get { return _destination; }
            set { _destination = value; OnPropertyChanged(); }
        }

        private string _ethertype;
        public string Ethertype
        {
            get { return _ethertype; }
            set { _ethertype = value; OnPropertyChanged(); }
        }

        private string _length;
        public string Length
        {
            get { return _length; }
            set { _length = value; OnPropertyChanged(); }
        }

        private string _info;
        public string Info
        {
            get { return _info; }
            set { _info = value; OnPropertyChanged(); }
        }

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
