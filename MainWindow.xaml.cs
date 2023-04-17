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
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;

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
        public bool IsAutoScrollEnabled { get; set; } = false;
        public ObservableCollection<int> FilteredPorts { get; set; } = new ObservableCollection<int>();
        private readonly StringBuilder _pktMonProcessOutputBuilder = new StringBuilder();
        private bool IsCapturing = false;
        private ObservableCollection<OutputData> _outputData = new ObservableCollection<OutputData>();
        private readonly Regex outputLineRegex = new Regex(@"(?<source>[A-Fa-f0-9\-]+) > (?<destination>[A-Fa-f0-9\-]+), ethertype (?<ethertype>\w+) \((?<etypecode>0x[A-Fa-f0-9]+)\), length (?<length>\d+): (?<info>.+)");
        private static readonly Regex infoRegex = new Regex(@"^(?<source>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(?<sourceport>\d+)\s*>\s*(?<destination>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(?<destinationport>\d+): (?<info>.+)$", RegexOptions.Compiled);
        private Process _pktMonProcess;
        private Process _pktMonStopProcess;
        private bool _processExited = false;
        private readonly System.Timers.Timer _scrollTimer = new System.Timers.Timer(700);
        private bool _scrollReady = true;
        private BlockingCollection<OutputData> _outputDataQueue = new BlockingCollection<OutputData>();
        private CancellationTokenSource _updateCts;
        private DispatcherTimer _dispatcherTimer;
        private BlockingCollection<OutputData> _outputBuffer;

        public MainWindow()
        {
            InitializeComponent();
            ProcessOutputDataQueue();
            _scrollTimer.Elapsed += (s, e) =>
            {
                _scrollReady = true;
                _scrollTimer.Stop();
            };
            ToggleTheme();
            _outputData = new ObservableCollection<OutputData>();
            OutputDataGrid.ItemsSource = _outputData;
            _outputBuffer = new BlockingCollection<OutputData>();
            DataContext = this;
            OutputDataGrid.ItemsSource = _outputData;
            System.Windows.Data.CollectionViewSource outputDataViewSource = (CollectionViewSource)FindResource("outputDataViewSource");
            outputDataViewSource.Source = _outputData;
            Closing += MainWindow_Closing;
        }
        private CancellationTokenSource _cts;
        private async void ProcessOutputDataQueue()
        {
            _cts = new CancellationTokenSource();

            await Task.Run(async () =>
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        var outputData = _outputDataQueue.Take(_cts.Token);

                        await Dispatcher.InvokeAsync(() =>
                        {
                            _outputData.Add(outputData);
                            if (_outputData.Count > int.Parse(MaxEvents.Text))
                            {
                                _outputData.RemoveAt(0);
                            }
                            Debug.WriteLine("Added to _outputData");
                            if (_scrollReady && AutoScrollCheckBox.IsChecked == true)
                            {
                                _scrollReady = false;
                                _scrollTimer.Start();
                                if (OutputDataGrid.Items.Count > 0)
                                {
                                    var lastItem = OutputDataGrid.Items[OutputDataGrid.Items.Count - 1];
                                    OutputDataGrid.ScrollIntoView(lastItem);
                                }
                            }
                        });
                    }
                    catch (OperationCanceledException)
                    {
                        // Task was canceled, exit the loop
                        break;
                    }
                }
            });
        }
        

        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            IsCapturing = false;
            StopCapture();
        }
        private void MaxEvents_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            e.Handled = !int.TryParse(e.Text, out _);
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
            StopCapture();
            if(SaveOutput.IsChecked == true)
            {
                var saveFileDialog = new SaveFileDialog();
                saveFileDialog.Filter = "Capture Files (*.pcapng)|*.pcapng|Capture Files (*.*)|*.*";
                saveFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                saveFileDialog.FileName = "output-" + DateTime.Now.ToString("yyyyMMddHHmmss") + ".pcapng"; ;

                if (saveFileDialog.ShowDialog() == true)
                {
                    string selectedFilePath = saveFileDialog.FileName;
                    // Do something with the selected file path  
                    // Save captured data to file
                    var convertToPcap = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = "/C pktmon pcapng PktMon.etl -o " + selectedFilePath,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    convertToPcap.Start();
                    convertToPcap.WaitForExit();
                    convertToPcap.Dispose();
                }
            }
            StartButton.IsEnabled = true;
            IsCapturing = false;
            RealTimeCheckbox.IsEnabled = true;
        }

        private void StartCapture()
        {
            RealTimeCheckbox.IsEnabled = false;
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
            var clearFilterProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/C pktmon filter remove",
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            clearFilterProcess.Start();
            clearFilterProcess.WaitForExit();
            clearFilterProcess.Dispose();
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
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    addFilterProcess.Start();
                    addFilterProcess.WaitForExit();
                    addFilterProcess.Dispose();
                }
            }
            if (FilterIPs.Items.Count > 0)
            {
                // Add IP filters
                foreach (string IP in FilterIPs.Items)
                {
                    var addFilterProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/C pktmon filter add -i {IP}",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    addFilterProcess.Start();
                    addFilterProcess.WaitForExit();
                    addFilterProcess.Dispose();
                }
            }
            // Clear output data and start packet capture
            _outputData.Clear();
            _pktMonProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            if (RealTimeCheckbox.IsChecked == true)
            {
                _pktMonProcess.StartInfo.Arguments = "/C pktmon start --etw --log-mode real-time";
            }
            else
            {
                _pktMonProcess.StartInfo.Arguments = "/C pktmon start --etw";
            }
            _pktMonProcess.Start();
            if (RealTimeCheckbox.IsChecked == true)
            {
                _pktMonProcess.OutputDataReceived += PktMonProcess_OutputDataReceived;                
                _pktMonProcess.BeginOutputReadLine();
                // Initialize the CancellationTokenSource and DispatcherTimer
                _updateCts = new CancellationTokenSource();
                _dispatcherTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(50) // Adjust the interval for better UI responsiveness
                };
                _dispatcherTimer.Tick += DispatcherTimer_Tick;
                _dispatcherTimer.Start();
            }
        }
        private void PktMonProcess_Exited(object sender, EventArgs e)
        {
            Debug.WriteLine("Process exited");
            _processExited = true;
        }
        private async void StopCapture()
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
            if (RealTimeCheckbox.IsChecked == true)
            {
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
            
                // Stop update task logic
                _updateCts.Cancel();
                _dispatcherTimer.Stop();
                _dispatcherTimer = null;

                // Process the remaining items in the _outputBuffer as batches
                var remainingItems = new List<OutputData>();
                while (_outputBuffer.TryTake(out var outputData))
                {
                    remainingItems.Add(outputData);
                    if (remainingItems.Count >= 100) // Adjust the batch size as needed
                    {
                        await BatchUpdateDataGrid(remainingItems);
                        remainingItems.Clear();
                    }
                }

                // Process any remaining items that didn't fill the last batch
                if (remainingItems.Count > 0)
                {
                    await BatchUpdateDataGrid(remainingItems);
                }
            }
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
            var match = outputLineRegex.Match(e.Data);
            if (match.Success)
            {                
                Task.Run(() =>
                {
                    Debug.WriteLine("Received data: " + e.Data);
                    MessageParser parser = new MessageParser();
                    Dictionary<string, string> result = parser.Parse(e.Data);
                    var outputData = new OutputData
                    {
                        Timestamp = DateTime.Now,
                        SourceIP = result["SourceIP"],
                        SourcePort = result["SourcePort"],
                        DestIP = result["DestIP"],
                        DestPort = result["DestPort"],
                        Info = result["Info"]
                    };

                    _outputDataQueue.Add(outputData);
                    

                }).ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        Debug.WriteLine("Error in background task: " + t.Exception);
                    }
                    Dispatcher.Invoke(() => ReattachExitedHandler());
                });
            }
        }
        private void ReattachExitedHandler()
        {
            _pktMonProcess.Exited += PktMonProcess_Exited;
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
        public class MessageParser
        {
            public Dictionary<string, string> Parse(string message)
            {
                Dictionary<string, string> result = new Dictionary<string, string>();
                string[] fields = message.Split(',');
                // parse source and destination MAC
                string[] MacValues = fields[0].Split('>');
                result["SourceMac"] = MacValues[0].Trim();
                result["DestMac"] = MacValues[1].Trim();
                // parse ethertype
                string[] ethType = fields[1].Trim().Split(' ');
                result["ethertype"] = ethType[1];
                string[] srcIPPort;
                string[] dstIPPort;
                string[] sourcedest;
                string[] InfoFields;
                if (ethType[1] == "IPv6")
                {
                    string[] ipfields = fields[2].Split(": ");
                    result["length"] = ipfields[0];
                    sourcedest = ipfields[1].Split('>');
                    result["Info"] = ipfields[2];
                    srcIPPort = sourcedest[0].Split('.');
                    dstIPPort = sourcedest[1].Split('.');
                    result["SourceIP"] = srcIPPort[0];
                    result["DestIP"] = dstIPPort[0];
                    try
                    {
                        result["SourcePort"] = srcIPPort[1];
                    }
                    catch
                    {
                        result["SourcePort"] = "N/A";
                    }
                    try
                    {
                        result["DestPort"] = dstIPPort[1];
                    }
                    catch
                    {
                        result["DestPort"] = "N/A";
                    }
                }
                else if (ethType[1] == "ARP")
                {
                    string[] ipfields = fields[2].Split(": ");
                    result["length"] = ipfields[0];
                    result["SourceIP"] = ipfields[1].Split(' ')[4];
                    result["SourcePort"] = "N/A";
                    result["DestIP"] = ipfields[1].Split(' ')[2];
                    result["DestPort"] = "N/A";
                    result["Info"] = ipfields[1];
                }
                else
                {
                    // parse length source IP and port, destination IP and port
                    string[] ipfields = fields[2].Split(':');
                    result["length"] = ipfields[0].Trim().Split(' ')[1];
                    sourcedest = ipfields[1].Split('>');
                    srcIPPort = sourcedest[0].Split('.');
                    result["SourceIP"] = srcIPPort[0] + "." + srcIPPort[1] + "." + srcIPPort[2] + "." + srcIPPort[3];
                    try
                    {
                        result["SourcePort"] = srcIPPort[4];
                    }
                    catch
                    {
                        result["SourcePort"] = "N/A";
                    }
                    dstIPPort = sourcedest[1].Split('.');
                    result["DestIP"] = dstIPPort[0] + "." + dstIPPort[1] + "." + dstIPPort[2] + "." + dstIPPort[3];
                    try
                    {
                        result["DestPort"] = dstIPPort[4];
                    }
                    catch
                    {
                        result["DestPort"] = "N/A";
                    }
                    // parse info
                    InfoFields = message.Trim().Split(':');
                    result["Info"] = string.Join(' ', InfoFields.Skip(2));
                }
                return result;
            }
        }
        private async Task BatchUpdateDataGrid(IEnumerable<OutputData> outputDataBatch)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                foreach (var outputData in outputDataBatch)
                {
                    _outputData.Add(outputData);
                    if (_outputData.Count > int.Parse(MaxEvents.Text))
                    {
                        _outputData.RemoveAt(0);
                    }
                }

                if (OutputDataGrid.Items.Count > 0)
                {
                    var lastItem = OutputDataGrid.Items[OutputDataGrid.Items.Count - 1];
                    OutputDataGrid.ScrollIntoView(lastItem);
                }
            });
        }
        private async void DispatcherTimer_Tick(object sender, EventArgs e)
        {
            var outputDataBatch = new List<OutputData>();
            while (_outputBuffer.TryTake(out var outputData, 0, _updateCts.Token))
            {
                outputDataBatch.Add(outputData);
                if (outputDataBatch.Count >= 50) // Adjust the batch size as needed
                {
                    await BatchUpdateDataGrid(outputDataBatch);
                    outputDataBatch.Clear();
                }
            }

            if (outputDataBatch.Count > 0)
            {
                await BatchUpdateDataGrid(outputDataBatch);
            }
        }

        private void RealTimeCheckbox_Checked(object sender, RoutedEventArgs e)
        {
            MaxEventsLabel.IsEnabled = true;
            MaxEvents.IsEnabled = true;
            OutputDataGrid.IsEnabled = true;
            ScrollViewer.IsEnabled = true;
        }
        private void RealTimeCheckbox_Unchecked(object sender, RoutedEventArgs e)
        {
            MaxEventsLabel.IsEnabled = false;
            MaxEvents.IsEnabled = false;
            OutputDataGrid.IsEnabled = false;
            ScrollViewer.IsEnabled = false;
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

        private string _sourceIP;
        public string SourceIP
        {
            get { return _sourceIP; }
            set { _sourceIP = value; OnPropertyChanged(); }
        }

        private string _sourcePort;
        public string SourcePort
        {
            get { return _sourcePort; }
            set { _sourcePort = value; OnPropertyChanged(); }
        }

        private string _destIP;
        public string DestIP
        {
            get { return _destIP; }
            set { _destIP = value; OnPropertyChanged(); }
        }

        private string _destPort;
        public string DestPort
        {
            get { return _destPort; }
            set { _destPort = value; OnPropertyChanged(); }
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
