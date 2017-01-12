using System;
using System.Text;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace TORComm.TestBed.Components.Distributed
{
    public class InboundMessageObject
    {
        public String message;
        public StringBuilder MessageBuilder;
        public InboundConnectionObject client;

        public IAsyncResult ReceiveAsync(AsyncCallback CallbackMethod)
        {
            return this.client.client.Client.BeginReceive(client.buffer, 0, client.buffer.Length, SocketFlags.None,
                        CallbackMethod, this);
        }

        public InboundMessageObject(InboundConnectionObject client)
        {
            this.client = client;
            this.message = String.Empty;
            this.MessageBuilder = new StringBuilder();
        }
    }

    public class PeeringAssignmentObject
    {
        public ConcurrentBag<String> ApprovedInboundPeers;
        public ConcurrentBag<String> ApprovedOutboundPeers;

        public PeeringAssignmentObject()
        {
            this.ApprovedInboundPeers = new ConcurrentBag<string>();
            this.ApprovedOutboundPeers = new ConcurrentBag<string>();
        }
    }

    public class PeeringTableObject
    {
        private String CurrentID;
        private TestBed.Distributed.Network.Relay ParentRelay;
        private ConcurrentDictionary<String, PeerAddressObject> PeerTable;

        public PeeringAssignmentObject PeeringAssignments;

        public void RecalculateAssignments()
        {
            if (this.PeerTable.Count > 1)
            {
                this.PeeringAssignments = new PeeringAssignmentObject();
                int RelayPosition = PeerTable.Keys.ToList<String>().IndexOf(CurrentID);
                int ConnectionCount = this.ParentRelay.NetworkParameters.MaxPeers % this.PeerTable.Count - 1;
                for(int i = 1; i != ConnectionCount; i++)
                {
                    PeeringAssignments.ApprovedOutboundPeers.Add(this.PeerTable.Keys.ElementAt((RelayPosition + i) % (PeerTable.Count - 1)));
                    PeeringAssignments.ApprovedInboundPeers.Add(this.PeerTable.Keys.ElementAt((RelayPosition - i) % (PeerTable.Count - 1)));
                }
            }
        }

        public void AddPeer(PeerAddressObject peer)
        {
            bool AddSuccessful = false;
            while (!(AddSuccessful))
            {
                this.PeerTable.TryAdd(peer.RelayAddress, peer);
            }
            this.RecalculateAssignments();
        }

        public PeerAddressObject GetPeerByAddress(String RelayAddress)
        {
            PeerAddressObject peer = null;
            if(this.PeerTable.ContainsKey(RelayAddress))
            {
                peer = this.PeerTable[RelayAddress];
            }
            return peer;
        }

        public PeeringTableObject(String CurrentID, TestBed.Distributed.Network.Relay ParentRelay)
        {
            this.CurrentID = CurrentID;
            this.ParentRelay = ParentRelay;
            this.PeeringAssignments = new PeeringAssignmentObject();
            this.PeerTable = new ConcurrentDictionary<string, PeerAddressObject>();
        }
    }

    public class PeerAddressObject
    {
        public int NetworkPort;
        public String RelayAddress;
        public String NetworkAddress;
        public TORComm.Security.RSA.KeyStorageProvider NetworkPublicKey;
        public TORComm.Security.RSA.KeyStorageProvider SigningPublicKey;

        public PeerAddressObject()
        {
            this.NetworkPort = 0;
            this.RelayAddress = String.Empty;
            this.NetworkAddress = String.Empty;
            this.NetworkPublicKey = new Security.RSA.KeyStorageProvider();
            this.SigningPublicKey = new Security.RSA.KeyStorageProvider();
        }
    }

    public class NetworkParameters
    {
        public int MaxPeers;
        public int RxBufferSize;

        public NetworkParameters()
        {
            this.MaxPeers = 0;
            this.RxBufferSize = 0;
        }
    }

    public class InboundConnectionObject
    {
        public bool active;
        public byte[] buffer;
        public int BufferSize;
        public TcpClient client;

        public void Dispose()
        {
            this.buffer = null;
            this.active = false;
            this.client.Close();
        }

        public void ResetBufferState()
        {
            this.buffer = new byte[this.BufferSize];
        }

        public InboundConnectionObject(TcpClient client, int buffersize)
        {
            this.client = client;
            this.BufferSize = buffersize;
            this.ResetBufferState();
            this.active = true;
        }

        public InboundConnectionObject(TcpClient client)
        {
            this.client = client;
            this.active = true;
            this.buffer = null;
        }

        public InboundConnectionObject()
        {
            this.client = null;
            this.buffer = null;
            this.active = false;
        }
    }

    public class InitialPeeringParameters
    {
        public int port;
        public string address;
        public bool IsFounder;

        public InitialPeeringParameters(int p = 0, string a = "", bool f = false)
        {
            this.port = p;
            this.address = a;
            this.IsFounder = f;
        }
    }
}