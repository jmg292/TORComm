using System;
using System.Net;
using System.Text;
using System.Net.Sockets;

namespace TORComm.TestBed.Components.Distributed
{
    public class InboundMessageObject
    {
        public String message;
        public StringBuilder MessageBuilder;
        public InboundConnectionObject client;

        public InboundMessageObject(InboundConnectionObject client)
        {
            this.client = client;
            this.message = String.Empty;
            this.MessageBuilder = new StringBuilder();
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