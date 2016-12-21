using System;
using System.IO;
using System.Threading;

namespace TORComm.Interface.CommandLine
{
    class CLInterface
    {
        private int ConnectionTimeout;
        private TORComm.Components.Network.ConnectionMode mode;

        private void TerminateApplication(int ExitCode=0)
        {
            Console.Write("[+] Stopping network transport service... ");
            TORComm.Active.NetworkTransport.Disconnect();
            Console.Write("Done.\n[+] Stopping network command interface... ");
            // Dispose CommandInterface
            Console.WriteLine("Done.\n[+] Stopping secure network connection...");
            TORComm.Active.TorProcess.Stop();
            Console.WriteLine("[+] All operations completed, exiting.");
            System.Environment.Exit(ExitCode);
        }

        private String GetPasswordFromConsole()
        {
            String ReturnValue = String.Empty;
            Console.Write("Authentication Required: ");
            while (true)
            {
                ConsoleKeyInfo PressedKey = Console.ReadKey();
                if ((PressedKey.Key != ConsoleKey.Backspace) && (PressedKey.Key != ConsoleKey.Enter))
                {
                    ReturnValue += PressedKey.KeyChar;
                    Console.Write("\b*");
                }
                else if (PressedKey.Key == ConsoleKey.Backspace)
                {
                    ReturnValue = ReturnValue.Substring(0, ReturnValue.Length - 1);
                    Console.Write("\b \b");
                }
                else if (PressedKey.Key == ConsoleKey.Enter)
                {
                    Console.Write("\n");
                    break;
                }
            }
            return ReturnValue;
        }

        private void CreateOrLoadRSAKeys()
        {
            Console.Clear();
            int RetryCount = 3;
            bool ActionSuccessful = false;
            while (RetryCount > 0)
            {
                if (File.Exists(TORComm.Active.KeyStore.KeyFilePath))
                {
                    ActionSuccessful = TORComm.Active.KeyStore.LoadSavedKey(this.GetPasswordFromConsole());
                    if(!(ActionSuccessful))
                    {
                        Console.WriteLine("[!] Invalid authentication provided, {0} attempts remaining.", --RetryCount);
                    }
                    else
                    {
                        Console.Clear();
                        Console.WriteLine("[+] Authentication successful, RSA keys loaded.");
                        break;
                    }
                }
                else
                {
                    Console.WriteLine("[+] Please provide a new encryption key.");
                    String password = this.GetPasswordFromConsole();
                    Console.WriteLine("[+] Please re-enter key for validation.");
                    String verification = this.GetPasswordFromConsole();
                    Console.Clear();
                    if(password == verification)
                    {
                        Console.WriteLine("[+] Generating new RSA keys, this will take a moment.");
                        TORComm.Active.KeyStore.CreateNewKey(password);
                        ActionSuccessful = true;
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[!] Encryption key mismatch, please try again.");
                    }
                }
            }
            if(!(ActionSuccessful))
            {
                Console.WriteLine("[!] Unable to create or load RSA keys, terminating application.");
                this.TerminateApplication();
            }
        }

        private void StartTORAndWaitForConnection()
        {
            int PercentComplete = 0;
            int TotalIterations = 0;
            TORComm.Active.TorProcess.Start();
            Console.WriteLine("");
            while (!(PercentComplete >= 100))
            {
                if(TotalIterations++ * 4 == this.ConnectionTimeout)
                {
                    Console.Clear();
                    Console.WriteLine("[!] ERROR: Timed out while waiting for secure network connection.");
                    Console.WriteLine("[+] Terminating application, please wait.");
                    this.TerminateApplication(1);
                }
                PercentComplete = TORComm.Active.TorProcess.GetBootstrappedStatus();
                Console.Write("[+] Establishing secure connection... ({0}%)\r", PercentComplete);
                Thread.Sleep(250);
            }
            Console.Clear();
            Console.WriteLine("[+] Secure network connection established.");
        }

        private void StartNetworkServices()
        {
            Console.Clear();
            if(this.mode == Components.Network.ConnectionMode.SERVER)
            {
                Console.Write("[+] Initializing secure network transport service... ");
                TORComm.Active.NetworkTransport.Bind(TORComm.Utilities.Network.GetUnusedPort());
                Console.WriteLine("Done.\n[+] Creating hidden service, this will take a moment.\n");
                this.StartTORAndWaitForConnection();
                Console.WriteLine("[+] Establishing control interface connection.");
                TORComm.Components.TorProcess.DynamicProperties ControlProperties = TORComm.Active.TorProcess.GetSessionProperties();
                TORComm.Active.CommandInterface.Connect(ControlProperties.ControlPort, ControlProperties.ControlPassword);
                while(!(TORComm.Active.CommandInterface.ConnectionReady))
                {
                    Thread.Sleep(500);
                }
                Console.WriteLine("\n[+] Successfully loaded {0} router objects.\n", TORComm.Active.RouterStorage.FastRouters.Count + TORComm.Active.RouterStorage.SlowRouters.Count);
                Console.WriteLine("[+] Fast router objects: {0}", TORComm.Active.RouterStorage.FastRouters.Count);
                Console.WriteLine("[+] Slow router objects: {0}", TORComm.Active.RouterStorage.SlowRouters.Count);
                Console.WriteLine("[+] Exit node identities: {0}", TORComm.Active.RouterStorage.ExitNodeIndex.Count);
                Console.WriteLine("[+] Guard node identities: {0}", TORComm.Active.RouterStorage.GuardNodeIndex.Count);
                Console.WriteLine("[+] Directory authorities: {0}", TORComm.Active.RouterStorage.DirectoryAuthorityIndex.Count);
                Console.WriteLine("[+] Hidden service directories: {0}", TORComm.Active.RouterStorage.HiddenServiceDirectoryIndex.Count);
                Console.WriteLine("[+] Attempting to establish intro circuit.");
                TORComm.Active.CommandInterface.CircuitHandler.GetCurrentCircuitStatus();
            }
        }

        private void GetOperationalMode()
        {
            Console.Clear();
            while (true)
            {
                Console.Write("[+] Choose operational mode:\n\t1.) Client\n\t2.) Server\n\n> ");
                int choice = Convert.ToInt32(Console.ReadLine());
                if(choice == 1)
                {
                    this.mode = TORComm.Components.Network.ConnectionMode.CLIENT;                    
                }
                else
                {
                    this.mode = TORComm.Components.Network.ConnectionMode.SERVER;
                }
                TORComm.Active.TorProcess.Initialize(this.mode);
                TORComm.Active.NetworkTransport.SetOperationalMode(this.mode);
                break;
            }
        }

        public void StartApplication()
        {
            this.GetOperationalMode();
            Console.Clear();
            this.CreateOrLoadRSAKeys();
            this.StartNetworkServices();
            Console.WriteLine("\n[+] Test completed, terminating application.\n");
            this.TerminateApplication();
        }

        public CLInterface(int Timeout=30)
        {
            Console.Clear();
            this.ConnectionTimeout = Timeout;
        }
    }
}
