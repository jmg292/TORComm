using System;
using System.IO;
using System.Diagnostics;
using System.Collections;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace TORComm.OperatingSystem
{
    public class TorProcess
    {

        private int SocksPort;
        private int ControlPort;

        private String TorPath;
        private String BasePath;
        private String SwapDirectory;
        private String SessionPassword;
        private String ServiceDirectory;
        private String HashedSessionPassword;
        
        private Process ControlledProcess;
        private ConcurrentQueue<String> StoredOutput;
        private TORComm.Components.Network.ConnectionMode MODE;

        private static String[] StaticConfiguration = new String[] {
            "AllowUnverifiedNodes middle,rendezvous",
            "Log info-err stdout",
            "AvoidDiskWrites 1",
            "Sandbox 1",
        };

        private void CleanSwapSpace()
        {
            foreach (String FileName in TORComm.Utilities.Filesystem.GetAllFilesInDirectory(this.SwapDirectory))
            {
                TORComm.Utilities.Filesystem.OverwriteAndDeleteFile(FileName);
            }
            Directory.Delete(this.SwapDirectory, true);
        }

        private void GetSessionPassword()
        {
            Process TorProcess = new Process();
            TorProcess.StartInfo.FileName = this.TorPath;
            TorProcess.StartInfo.UseShellExecute = false;
            TorProcess.StartInfo.RedirectStandardOutput = true;
            TorProcess.StartInfo.Arguments = "--quiet --hash-password ";
            TorProcess.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            SHA512CryptoServiceProvider sha = new SHA512CryptoServiceProvider();
            RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
            Byte[] seed = new Byte[4096];
            RNG.GetNonZeroBytes(seed);
            Console.WriteLine("\t + Generating dynamic session password.");
            this.SessionPassword = Convert.ToBase64String(sha.ComputeHash(seed)).Replace("=", "");
            TorProcess.StartInfo.Arguments += this.SessionPassword;
            Console.WriteLine("\t + Generating password configuration item.");
            TorProcess.Start();
            TorProcess.WaitForExit();
            Console.WriteLine("\t + Retrieving password config data.");
            using (StreamReader reader = TorProcess.StandardOutput)
            {
                this.HashedSessionPassword = reader.ReadLine();
            }
            TorProcess.Dispose();
            RNG.Dispose();
            sha.Dispose();
            Console.WriteLine("\t + Password configured successfully.");
        }

        private void AutoConfigure()
        {

            this.GetSessionPassword();
            Console.WriteLine("\t + Generating SOCKS port assignment");
            this.SocksPort = TORComm.Utilities.Network.GetUnusedPort();
            Console.WriteLine("\t + Generating control port assignment.");
            this.ControlPort = TORComm.Utilities.Network.GetUnusedPort();
            Console.WriteLine("\t + Creating application data directory.");
            String DataDir = Path.Combine(this.SwapDirectory, "data");
            Console.WriteLine("\t + Creating config path location.");
            String ConfigPath = Path.Combine(this.SwapDirectory, "config");
            if (!(Directory.Exists(DataDir)))
            {
                Directory.CreateDirectory(DataDir);
            }
            Console.Write("\t + Setting dynamic config items... ");
            ArrayList ActualConfiguration = new ArrayList();
            String[] DynamicConfig = new String[] {
                String.Format("DataDirectory {0}", DataDir),
                String.Format("SocksPort {0}", this.SocksPort),
                String.Format("ControlPort {0}", this.ControlPort),
                String.Format("HashedControlPassword {0}", this.HashedSessionPassword),
                String.Format("GeoIPFile {0}", Path.Combine(this.BasePath, "lib", "geoip")),
                String.Format("GeoIPv6File {0}", Path.Combine(this.BasePath, "lib", "geoip6"))
            };
            ActualConfiguration.AddRange(DynamicConfig);
            Console.Write("Done.\n\t + Setting static config items... ");
            ActualConfiguration.AddRange(StaticConfiguration);
            Console.Write("Done.\n\t + Setting runtime-specific config items.... ");
            if (this.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
            {
                // Client specific settings
                ActualConfiguration.Add("FascistFirewall 1");
            }
            else
            {
                // Hidden Service specific settings
                this.ServiceDirectory = Path.Combine(DataDir, Guid.NewGuid().ToString());
                Directory.CreateDirectory(this.ServiceDirectory);
                ActualConfiguration.Add(String.Format("HiddenServiceDir {0}", this.ServiceDirectory));
                ActualConfiguration.Add(String.Format("HiddenServicePort 80 {0}", TORComm.Active.NetworkTransport.ServiceAddress));
                ActualConfiguration.Add("HiddenServiceMaxStreams 2");
                ActualConfiguration.Add("HiddenServiceMaxStreamsCloseCircuit 1");
            }
            Console.Write("Done.\n\t + Writing application configuration... ");
            using (FileStream fstream = new FileStream(ConfigPath, FileMode.OpenOrCreate))
            {
                using (StreamWriter writer = new StreamWriter(fstream))
                {
                    foreach (String setting in ActualConfiguration)
                    {
                        writer.WriteLine(setting);
                    }
                }
            }
            Console.WriteLine("Done.\n\t + Automatic configuration complete.");
        }

        public void Initialize(TORComm.Components.Network.ConnectionMode mode, String ExePath = null)
        {
            this.MODE = mode;
            this.ServiceDirectory = String.Empty;
            this.StoredOutput = new ConcurrentQueue<string>();
            this.BasePath = AppDomain.CurrentDomain.BaseDirectory;
            this.SwapDirectory = Path.Combine(this.BasePath, "swap");
            if (String.IsNullOrEmpty(ExePath))
            {
                this.TorPath = Path.Combine(this.BasePath, "bin", "tor.exe");
            }
            else
            {
                this.TorPath = ExePath;
            }
            if (!(File.Exists(this.TorPath)))
            {
                throw new FileNotFoundException(String.Format("TOR not found in path: {0}", this.TorPath));
            }
            if (!(Directory.Exists(this.SwapDirectory)))
            {
                Directory.CreateDirectory(this.SwapDirectory);
            }
        }

        public TORComm.Components.TorProcess.DynamicProperties GetSessionProperties()
        {
            TORComm.Components.TorProcess.DynamicProperties SessionProperties = new TORComm.Components.TorProcess.DynamicProperties();
            SessionProperties.SocksPort = this.SocksPort;
            SessionProperties.ControlPort = this.ControlPort;
            SessionProperties.ControlPassword = this.SessionPassword;
            return SessionProperties;
        }

        public int GetBootstrappedStatus()
        {
            String BootstrapPercentage = String.Empty;
            Regex expression = new Regex(@"(Bootstrapped)\s[\d]{1,3}[%]");
            String[] CapturedOutput = this.StoredOutput.ToArray();
            foreach (String line in CapturedOutput)
            {
                if (!(String.IsNullOrEmpty(line)))
                {
                    Match ExpressionMatch = expression.Match(line);
                    if (ExpressionMatch.Success)
                    {
                        BootstrapPercentage = ExpressionMatch.Groups[0].Value;
                    }
                }
            }
            if (String.IsNullOrEmpty(BootstrapPercentage))
            {
                return 0;
            }
            else
            {
                return Convert.ToInt32(Regex.Match(BootstrapPercentage, @"\d+").Value);
            }
        }

        public String[] GetOutput()
        {
            ArrayList ControlledProcessOutput = new ArrayList();
            while (this.StoredOutput.Count > 0)
            {
                bool DequeueSuccess = false;
                String CapturedOutput = String.Empty;
                while (!(DequeueSuccess))
                {
                    DequeueSuccess = this.StoredOutput.TryDequeue(out CapturedOutput);
                }
                ControlledProcessOutput.Add(CapturedOutput);
            }
            return (String[])ControlledProcessOutput.ToArray(typeof(string));
        }

        public String GetHiddenServiceAddress()
        {
            String ReturnValue = String.Empty;
            if (Directory.Exists(this.ServiceDirectory))
            {
                String HostFile = Path.Combine(this.ServiceDirectory, "hostname");
                if (File.Exists(HostFile))
                {
                    using (FileStream fstream = new FileStream(HostFile, FileMode.Open, FileAccess.Read))
                    {
                        using (StreamReader reader = new StreamReader(fstream))
                        {
                            ReturnValue = reader.ReadLine();
                        }
                    }
                }
            }
            return ReturnValue;
        }

        public void Stop()
        {
            Console.Write("\n\t + Sending SIGTERM to process... ");
            this.ControlledProcess.Kill();
            Console.Write("Done.\n\t + Disposing process object... ");
            this.ControlledProcess.Dispose();
            Console.Write("Done.\n\t + Cleaning SWAP space... ");
            this.CleanSwapSpace();
            Console.Write("Done.\n\n[+] Cleanup operations completed.\n");
        }

        public void Start()
        {
            this.AutoConfigure();
            Console.WriteLine("\t + Generated dynamic configuration.");
            ProcessStartInfo StartInfo = new ProcessStartInfo();
            StartInfo.CreateNoWindow = true;
            StartInfo.UseShellExecute = false;
            StartInfo.FileName = this.TorPath;
            StartInfo.RedirectStandardOutput = true;
            Console.WriteLine("\t + Configured process start information.");
            StartInfo.Arguments = String.Format("-f \"{0}\"", Path.Combine(this.SwapDirectory, "config"));
            this.ControlledProcess = new Process();
            this.ControlledProcess.StartInfo = StartInfo;
            Console.WriteLine("\t + Setting process event handler.");
            this.ControlledProcess.OutputDataReceived += new DataReceivedEventHandler(
                delegate (Object sender, DataReceivedEventArgs ProcessOutput)
                {
                    this.StoredOutput.Enqueue(ProcessOutput.Data);
                }
            );
            Console.WriteLine("\t + Invoking process start method.");
            this.ControlledProcess.Start();
            Console.WriteLine("\t + Starting async read.");
            this.ControlledProcess.BeginOutputReadLine();
        }

        public TorProcess()
        {
        }
    }
}