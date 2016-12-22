using System;
using System.IO;
using System.Net;
using System.Xml;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Collections;
using System.Xml.Serialization;

namespace TORComm.Network.ControlProtocol
{
    public class NetworkStatus
    {
        private String RouterStorageFile;
        private CommandInterface ControlPort;

        private TORComm.Components.Network.RouterObject NewRouterFromArray(String[] RouterStatus)
        {
            /*
             * Parser specifications obtained from torspec/dir-spec.txt
             * Section 3.4.1. "Vote and consensus status document formats"
             * Current web address as of 12/12/2016:
             * https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt 
             */
            TORComm.Components.Network.RouterObject NewRouter = new Components.Network.RouterObject();
            foreach (String line in RouterStatus)
            {
                String[] SplitLine = line.Split(' ');
                switch (SplitLine[0])
                {
                    case "r":
                        NewRouter.nickname = SplitLine[1];
                        NewRouter.identity = SplitLine[2];
                        NewRouter.digest = SplitLine[3];
                        NewRouter.address = SplitLine[6];
                        for (int n = 7; n < SplitLine.Length - 1; n++)
                        {
                            NewRouter.Ports.Add(Convert.ToInt32(SplitLine[n]));
                        }
                        break;

                    case "s":
                        bool RequirementsMet = true;
                        foreach (String RequiredFlag in TORComm.Components.Network.RequiredRouterFlags)
                        {
                            if (!(SplitLine.Contains<String>(RequiredFlag)))
                            {
                                RequirementsMet = false;
                            }
                        }
                        if (RequirementsMet)
                        {
                            NewRouter.IsValid = true;
                            NewRouter.IsStable = true;
                            NewRouter.IsRunning = true;
                            if (SplitLine.Contains<String>("Fast"))
                            {
                                NewRouter.IsFast = true;
                            }
                            if (SplitLine.Contains<String>("Exit"))
                            {
                                NewRouter.IsExit = true;
                            }
                            if (SplitLine.Contains<String>("Guard"))
                            {
                                NewRouter.IsGuard = true;
                            }
                            if (SplitLine.Contains<String>("HSDir"))
                            {
                                NewRouter.IsHSDirectory = true;
                            }
                            if (SplitLine.Contains<String>("Authority"))
                            {
                                NewRouter.IsDirectoryAuthority = true;
                            }
                        }
                        else
                        {
                            return null;
                        }
                        break;

                    case "w":
                        NewRouter.bandwidth = Convert.ToInt32(SplitLine[1].Split('=')[1]);
                        break;

                    default:
                        // Per tor-spec.txt, any unknown lines should be ignored
                        continue;
                }
            }
            return NewRouter;
        }

        private void ProcessAndSortRouter(TORComm.Components.Network.RouterObject router)
        {
            if (router != null)
            {
                if (router.IsFast)
                {
                    if (!(TORComm.Active.RouterStorage.FastRouters.ContainsKey(router.identity)))
                    {
                        if (router.IsExit)
                        {
                            TORComm.Active.RouterStorage.ExitNodeIndex.Add(router.identity);
                        }
                        if (router.IsGuard)
                        {
                            TORComm.Active.RouterStorage.GuardNodeIndex.Add(router.identity);
                        }
                        if (router.IsDirectoryAuthority)
                        {
                            TORComm.Active.RouterStorage.DirectoryAuthorityIndex.Add(router.identity);
                        }
                        if (router.IsHSDirectory)
                        {
                            TORComm.Active.RouterStorage.HiddenServiceDirectoryIndex.Add(router.identity);
                        }
                        bool AddSuccessful = false;
                        while (!(AddSuccessful))
                        {
                            AddSuccessful = TORComm.Active.RouterStorage.FastRouters.TryAdd(router.identity, router);
                        }
                    }
                }
                else
                {
                    if (!(TORComm.Active.RouterStorage.SlowRouters.ContainsKey(router.identity)))
                    {
                        bool AddSuccessful = false;
                        while (!(AddSuccessful))
                        {
                            AddSuccessful = TORComm.Active.RouterStorage.SlowRouters.TryAdd(router.identity, router);
                        }
                    }
                }
            }
            return;
        }

        private void GetStatusFromController()
        {
            ArrayList TempStorage = new ArrayList();
            String NetworkStatus = this.ControlPort.SendCommand("GETINFO ns/all");
            if (ControlPort.ResponseOK(NetworkStatus))
            {
                // First line of status message is <StatusCode>+ns/all=, it's irrelevant to this operation as long as the response code is 250 (OK)
                TempStorage.AddRange(NetworkStatus.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None).Skip(1).ToArray<String>());

                // Last two lines will be "\r\n.\r\n250 OK", we can disregard these if the response code is OK
                TempStorage.RemoveRange(TempStorage.Count - 2, 2);

                ArrayList RouterStatus = new ArrayList();
                for (int i = 0; i < TempStorage.Count; i++)
                {
                    /*
                     * Microdescriptor size can change at any time.  We know that the microdescriptor is for a new router if 
                     * the line starts with an "r".  See torspec/dir-spec.txt section 3.4.1 "Vote Consensus Status Document Formats"
                     * for more information.  Current web address as of 12/12/2016: https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt
                     */
                    if (((String)TempStorage[i]).StartsWith("r"))
                    {
                        if (RouterStatus.Count > 0)
                        {
                            this.ProcessAndSortRouter(this.NewRouterFromArray((String[])RouterStatus.ToArray(typeof(String))));
                        }
                        RouterStatus = new ArrayList();
                    }
                    RouterStatus.Add(TempStorage[i]);
                }
            }
            else
            {
                throw new SocketException(167);
            }
            return;
        }

        private void GetStatusFromStorageFile()
        {
            if (File.Exists(this.RouterStorageFile))
            {
                String FileContents = String.Empty;
                using (FileStream fstream = new FileStream(this.RouterStorageFile, FileMode.Open, FileAccess.Read))
                {
                    using (StreamReader reader = new StreamReader(fstream))
                    {
                        FileContents = reader.ReadToEnd();
                    }
                }
                FileContents = TORComm.Security.RSA.CryptoInterface.DecryptString(FileContents);
                if (!(String.IsNullOrEmpty(FileContents)))
                {
                    String XmlString = String.Empty;
                    XmlSerializer serializer = new XmlSerializer(typeof(TORComm.Components.Network.RouterObject));
                    foreach (String line in FileContents.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None))
                    {
                        using (MemoryStream mstream = new MemoryStream())
                        {
                            using (BinaryWriter writer = new BinaryWriter(mstream, new System.Text.UTF8Encoding(false), true))
                            {
                                writer.Write(Convert.FromBase64String(line));
                            }
                            XmlString = System.Text.Encoding.UTF8.GetString(mstream.ToArray());
                        }
                        if (!(String.IsNullOrWhiteSpace(XmlString) || String.IsNullOrEmpty(XmlString)))
                        {
                            XmlDocument SerializedDocument = new XmlDocument();
                            SerializedDocument.LoadXml(XmlString);
                            TORComm.Components.Network.RouterObject router = (TORComm.Components.Network.RouterObject)serializer.Deserialize((XmlReader)new XmlNodeReader(SerializedDocument));
                            this.ProcessAndSortRouter(router);
                        }
                    }
                }
                else
                {
                    throw new FileLoadException(String.Format("Unable to load protected document.  This may indicate that the document has been tampered with.\nDocument location: {0} ",
                        this.RouterStorageFile));
                }
            }
        }

        public void SaveStatus()
        {
            if (TORComm.Active.RouterStorage.FastRouters.Count > 0 || TORComm.Active.RouterStorage.SlowRouters.Count > 0)
            {
                String NetworkInfo = String.Empty;
                using (MemoryStream mstream = new MemoryStream())
                {
                    using (StreamWriter writer = new StreamWriter(mstream, new System.Text.UTF8Encoding(false)))
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(TORComm.Components.Network.RouterObject));
                        foreach (TORComm.Components.Network.RouterObject router in TORComm.Active.RouterStorage.FastRouters.Values)
                        {
                            /* 
                             * Serializing in this way stores every serialized router object on a separate line.
                             * It makes for a larger file, but it's much easier to parse later.
                             */
                            String LineObject = String.Empty;
                            using (MemoryStream m2stream = new MemoryStream())
                            {
                                using (StreamWriter m2writer = new StreamWriter(m2stream, new System.Text.UTF8Encoding(false)))
                                {
                                    serializer.Serialize(m2writer, router);
                                }

                                LineObject = Convert.ToBase64String(m2stream.ToArray());
                            }
                            writer.WriteLine(LineObject);
                        }
                        foreach (TORComm.Components.Network.RouterObject router in TORComm.Active.RouterStorage.SlowRouters.Values)
                        {
                            String LineObject = String.Empty;
                            using (MemoryStream m2stream = new MemoryStream())
                            {
                                using (StreamWriter m2writer = new StreamWriter(m2stream, new System.Text.UTF8Encoding(false)))
                                {
                                    serializer.Serialize(m2writer, router);
                                }

                                LineObject = Convert.ToBase64String(m2stream.ToArray());
                            }
                            writer.WriteLine(LineObject);
                        }
                    }
                    NetworkInfo = System.Text.Encoding.UTF8.GetString(mstream.ToArray());
                }
                NetworkInfo = TORComm.Security.RSA.CryptoInterface.EncryptString(NetworkInfo);
                using (FileStream fstream = new FileStream(this.RouterStorageFile, FileMode.Create, FileAccess.Write))
                {
                    using (StreamWriter writer = new StreamWriter(fstream))
                    {
                        writer.Write(NetworkInfo);
                    }
                }
            }
        }

        public void LoadStatus()
        {
            if (File.Exists(this.RouterStorageFile))
            {
                this.GetStatusFromStorageFile();
            }
            else
            {
                this.GetStatusFromController();
                this.SaveStatus();
            }
        }

        public bool SetCountryForNode(String RouterId, String IPAddr)
        {
            bool OperationSuccessful = false;
            String ResultData = this.ControlPort.SendCommand(String.Format("GETINFO ip-to-country/{0}", IPAddr));
            if(this.ControlPort.ResponseOK(ResultData))
            {
                String CountryCode = ResultData.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None)[0].Split('=')[1];
                if(TORComm.Active.RouterStorage.FastRouters.ContainsKey(RouterId))
                {
                    TORComm.Active.RouterStorage.FastRouters[RouterId].CountryCode = CountryCode;
                    OperationSuccessful = true;
                }
                else if (TORComm.Active.RouterStorage.SlowRouters.ContainsKey(RouterId))
                {
                    TORComm.Active.RouterStorage.SlowRouters[RouterId].CountryCode = CountryCode;
                    OperationSuccessful = true;
                }
            }
            return OperationSuccessful;
        }

        public bool UpdateStatusForNode(String ORIdentity)
        {
            bool ExistFlag = false;
            bool RemoveSuccess = false;
            bool OperationSuccess = false;
            TORComm.Components.Network.RouterObject router = null;
            if(TORComm.Active.RouterStorage.FastRouters.ContainsKey(ORIdentity))
            {
                ExistFlag = true;
                while (!(RemoveSuccess))
                {
                    RemoveSuccess = TORComm.Active.RouterStorage.FastRouters.TryRemove(ORIdentity, out router);
                }
            }
            else if (TORComm.Active.RouterStorage.SlowRouters.ContainsKey(ORIdentity))
            {
                ExistFlag = true;
                while (!(RemoveSuccess))
                {
                    RemoveSuccess = TORComm.Active.RouterStorage.SlowRouters.TryRemove(ORIdentity, out router);
                }
            }
            if(ExistFlag && router != null)
            {
                ArrayList TempStorage = new ArrayList();
                Console.Write("\n\t+ Querying control port... ");
                String ResultData = this.ControlPort.SendCommand(String.Format("GETINFO ns/name/{0}", router.nickname));
                Console.WriteLine("Done.");
                if (this.ControlPort.ResponseOK(ResultData))
                {
                    Console.WriteLine("\t+ Processing updated information.");
                    TempStorage.AddRange(ResultData.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None).Skip(1).ToArray());
                    TempStorage.RemoveRange(TempStorage.Count - 2, 2);
                    router = this.NewRouterFromArray((String[])TempStorage.ToArray(typeof(string)));
                    if (router != null)
                    {
                        Console.WriteLine("\t+ New object created, validating status flags.");
                        if (router.IsRunning && router.IsStable && router.IsValid)
                        {
                            Console.WriteLine("\t+ Processing router: {0}", router.nickname);
                            this.ProcessAndSortRouter(router);
                            OperationSuccess = this.SetCountryForNode(router.identity, router.address);
                            Console.WriteLine("\t+ Router location: {0}", TORComm.Active.RouterStorage.SlowRouters[router.identity].CountryCode);
                        }
                    }
                }
            }
            if(OperationSuccess)
            {
                Console.WriteLine("\n[+] Successfully updated router status.\n");
            }
            return OperationSuccess;
        }

        public NetworkStatus(CommandInterface control)
        {
            this.ControlPort = control;
            this.RouterStorageFile = Path.Combine(TORComm.Active.StoragePath, "routers.bin");
        }
    }

    public class CircuitCoordinator
    {
        private CommandInterface ControlPort;

        private TORComm.Components.Network.RouterObject[] GetSlowRouterGroup(int Count=3)
        {
            ArrayList ReturnValue = new ArrayList();
            String[] RouterIDs = TORComm.Active.RouterStorage.SlowRouters.Keys.ToArray();
            while(!(ReturnValue.Count == Count))
            {
                String RouterId = RouterIDs[TORComm.Utilities.Security.GetRandomInt(RouterIDs.Count() - 1)];
                if(TORComm.Active.RouterStorage.SlowRouters.ContainsKey(RouterId))
                {
                    Console.WriteLine("\n[+] Getting updated status for router: {0}", RouterId);
                    if(this.ControlPort.StatusHandler.UpdateStatusForNode(RouterId))
                    {
                        ReturnValue.Add(TORComm.Active.RouterStorage.SlowRouters[RouterId]);
                    }
                }
            }
            return (TORComm.Components.Network.RouterObject[])ReturnValue.ToArray(typeof(TORComm.Components.Network.RouterObject));
        }

        private TORComm.Components.Network.CircuitObject GetCircuitFromString(String CircuitInfo)
        {
            String[] CircuitInfoArray = CircuitInfo.Split(' ');
            TORComm.Components.Network.CircuitObject NewCircuit = new Components.Network.CircuitObject();
            NewCircuit.identity = CircuitInfoArray[0];
            switch(CircuitInfoArray[1])
            {
                case "LAUNCHED":
                    NewCircuit.Status = Components.Network.CircuitStatus.LAUNCHED;
                    break;

                case "BUILT":
                    NewCircuit.Status = Components.Network.CircuitStatus.BUILT;
                    break;

                case "EXTENDED":
                    NewCircuit.Status = Components.Network.CircuitStatus.EXTENDED;
                    break;

                case "FAILED":
                    NewCircuit.Status = Components.Network.CircuitStatus.FAILED;
                    break;

                case "CLOSED":
                    NewCircuit.Status = Components.Network.CircuitStatus.CLOSED;
                    break;

                default:
                    // If the status isn't one of the above strings, something went horribly wrong.  Return null.
                    return null;
            }
            // Process the remaining line items before identifying the individual routers that compose the circuit
            for(int i = 3; i < CircuitInfoArray.Count(); i++)
            {
                String[] StatusItem = CircuitInfoArray[i].Split('=');
                if(StatusItem.Count() == 2) // Just in case there are additional items in a format we haven't accounted for
                {
                    switch (StatusItem[0])
                    {
                        case "PURPOSE":
                            switch(StatusItem[1])
                            {
                                case "GENERAL":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.GENERAL;
                                    break;

                                case "HS_CLIENT_INTRO":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.HS_CLIENT_INTRO;
                                    break;

                                case "HS_CLIENT_REND":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.HS_CLIENT_REND;
                                    break;

                                case "HS_SERVICE_INTRO":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.HS_SERVICE_INTRO;
                                    break;

                                case "HS_SERVICE_REND":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.HS_SERVICE_REND;
                                    break;

                                case "TESTING":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.TESTING;
                                    break;

                                case "CONTROLLER":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.CONTROLLER;
                                    break;

                                case "MEASURE_TIMEOUT":
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.MEASURE_TIMEOUT;
                                    break;

                                default:
                                    NewCircuit.Purpose = Components.Network.CircuitPurpose.UNLISTED_UNKNOWN;
                                    break;
                            }
                            break;

                        case "TIME_CREATED":
                            NewCircuit.CreationTime = DateTime.Parse(StatusItem[1], System.Globalization.CultureInfo.InvariantCulture);
                            break;

                        default:
                            // Skip anything we don't have parsing rules for
                            continue;
                    }
                }
            }
            ArrayList RouterList = new ArrayList();
            // Time to retrieve the stored object representing each router in the circuit
            foreach (String RouterInfo in CircuitInfoArray[2].Split(','))
            {
                TORComm.Components.Network.RouterObject router = TORComm.Network.RouterManagement.GetRouterByName(RouterInfo.Split('~')[1]);
                if(router != null)
                {
                    // Make sure we have the country code info for each router
                    if (String.IsNullOrEmpty(router.CountryCode))
                    {
                        this.ControlPort.StatusHandler.SetCountryForNode(router.identity, router.address);
                        // Since we had to update the stored router object, make sure our copy is up to date
                        if(router.IsFast)
                        {
                            router = TORComm.Active.RouterStorage.FastRouters[router.identity];
                        }
                        else
                        {
                            router = TORComm.Active.RouterStorage.SlowRouters[router.identity];
                        }
                    }
                    RouterList.Add(router);
                }
            }
            NewCircuit.Routers = (TORComm.Components.Network.RouterObject[])RouterList.ToArray(typeof(TORComm.Components.Network.RouterObject));
            return NewCircuit;
        }

        public bool GetCurrentCircuitStatus()
        {
            bool OperationSuccessful = false;
            String ControlResponse = this.ControlPort.SendCommand("GETINFO circuit-status");
            if (this.ControlPort.ResponseOK(ControlResponse))
            {
                ArrayList TempStorage = new ArrayList();
                TempStorage.AddRange(ControlResponse.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None).Skip(1).ToArray());
                TempStorage.RemoveRange(TempStorage.Count - 2, 2);
                foreach(String CircuitInfo in TempStorage)
                {
                    bool AdditionSuccessful = false;
                    TORComm.Components.Network.CircuitObject circuit = this.GetCircuitFromString(CircuitInfo);
                    while(!(AdditionSuccessful))
                    {
                        AdditionSuccessful = TORComm.Active.CircuitStorage.TryAdd(circuit.identity, circuit);
                    }
                }
            }
            return OperationSuccessful;
        }

        public CircuitCoordinator(CommandInterface control)
        {
            this.ControlPort = control;
        }
    }

    public class CommandInterface
    {
        public bool connected;
        public bool authenticated;
        public bool ConnectionReady;

        public NetworkStatus StatusHandler;
        public CircuitCoordinator CircuitHandler;

        private int ControlPort;
        private string ControlPassword;

        private TcpClient client;

        private String ReceiveResponse()
        {
            String RetVal = String.Empty;
            ArrayList TruncateBuffer = new ArrayList();
            int PreviousTimeout = this.client.Client.ReceiveTimeout;
            this.client.Client.ReceiveTimeout = 250;
            try
            {
                while (true)
                {
                    try
                    {
                        Byte[] RxBuffer = new Byte[40960];
                        this.client.Client.Receive(RxBuffer);
                        foreach (byte value in RxBuffer)
                        {
                            if (value > 0)
                            {
                                TruncateBuffer.Add((byte)value);
                            }
                        }
                    }
                    catch (SocketException)
                    {
                        break;
                    }
                }
                RetVal = System.Text.Encoding.ASCII.GetString((Byte[])TruncateBuffer.ToArray(typeof(byte))).TrimEnd('\n').TrimEnd('\r');
            }
            catch (SocketException)
            {
                Console.WriteLine("[!] Exception while receiving control response.");
            }
            finally
            {
                this.client.Client.ReceiveTimeout = PreviousTimeout;
            }
            return RetVal;
        }

        public bool ResponseOK(String response)
        {
            return response.StartsWith("250");
        }

        public String SendCommand(String command)
        {
            if (this.client.Connected)
            {
                if (!(command.EndsWith("\r\n")))
                {
                    command += "\r\n";
                }
                this.client.Client.Send(System.Text.Encoding.ASCII.GetBytes(command));
                return this.ReceiveResponse();
            }
            else
            {
                throw new ProtocolViolationException("Client is not connected!");
            }
        }

        private void AsyncAssociationHandler(IAsyncResult result)
        {
            this.client = (TcpClient)result.AsyncState;
            if (this.client.Connected)
            {
                Console.WriteLine("[+] Connected to control port, Transmitting AUTHENTICATE token.");
                String response = this.SendCommand(String.Format("AUTHENTICATE \"{0}\"", this.ControlPassword));
                if (this.ResponseOK(response))
                {
                    this.authenticated = true;
                    this.StatusHandler = new NetworkStatus(this);
                    this.CircuitHandler = new CircuitCoordinator(this);
                    Console.WriteLine("[+] Connection established and authenticated, querying network status.");
                    this.StatusHandler.LoadStatus();
                    this.ConnectionReady = true;
                }
                else
                {
                    Console.WriteLine("[!] Unable to establish authentication.");
                }
            }
            else
            {
                Console.WriteLine("[!] Unable to connect to control port.");
            }
        }

        public void Connect(int ControlPort, String ControlPassword, int Timeout=10)
        {
            this.ControlPort = ControlPort;
            this.ControlPassword = ControlPassword;
            this.client.Client.ReceiveTimeout = Timeout * 1000;
            this.client.BeginConnect("127.0.0.1", ControlPort, new AsyncCallback(this.AsyncAssociationHandler), this.client);
        }

        public CommandInterface()
        {
            this.connected = false;
            this.authenticated = false;
            this.client = new TcpClient();
        }
    }
}