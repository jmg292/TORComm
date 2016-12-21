using System;
using System.IO;
using System.Collections.Concurrent;

namespace TORComm
{
    public static class Active
    {
        public static String StoragePath;
        public static OperatingSystem.TorProcess TorProcess;
        public static Security.RSA.KeyStorageProvider KeyStore;
        public static Network.TransportProtocol NetworkTransport;
        public static Components.Network.RouterStorageObject RouterStorage;
        public static Network.ControlProtocol.CommandInterface CommandInterface;
        public static ConcurrentDictionary<String, TORComm.Components.Network.CircuitObject> CircuitStorage;

        static Active()
        {
            TORComm.Active.StoragePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "etc");
            if (!(Directory.Exists(TORComm.Active.StoragePath)))
            {
                Directory.CreateDirectory(TORComm.Active.StoragePath);
            }
            TORComm.Active.TorProcess = new OperatingSystem.TorProcess();
            TORComm.Active.KeyStore = new Security.RSA.KeyStorageProvider();
            TORComm.Active.NetworkTransport = new Network.TransportProtocol();
            TORComm.Active.RouterStorage = new Components.Network.RouterStorageObject();
            TORComm.Active.CommandInterface = new Network.ControlProtocol.CommandInterface();
            TORComm.Active.CircuitStorage = new ConcurrentDictionary<String, Components.Network.CircuitObject>();
        }
    }
}