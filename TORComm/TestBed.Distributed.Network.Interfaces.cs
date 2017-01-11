using System;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Collections.Concurrent;

using TORComm.TestBed.Components.Distributed;

namespace TORComm.TestBed.Distributed.Network.Interfaces
{
    public class InboundInterface
    {
        public int BoundPort;

        private Relay ParentRelay;
        private TcpListener NetworkInterface;
        private ConcurrentBag<InboundConnectionObject> AcceptedPeers;

        public delegate void PeeringRequestEventHandler(Object sender, InboundConnectionObject client);
        public delegate void MessageReceivedEventHandler(Object sender, InboundMessageObject MessageContainer);

        public PeeringRequestEventHandler PeeringRequestProcessors;
        public MessageReceivedEventHandler InboundMessageProcessors;

        private void NotifyConnectionRequest(InboundConnectionObject client)
        {
            if(this.PeeringRequestProcessors != null)
            {
                this.PeeringRequestProcessors(this, client);
            }
            else
            {
                this.DenyPeeringRequest(client);
            }
        }

        private void NotifyMessageReceived(InboundMessageObject MessageContainer)
        {
            if(this.InboundMessageProcessors != null)
            {
                this.InboundMessageProcessors(this, MessageContainer);
            }
        }

        private void ProcessConnectionRequest(IAsyncResult result)
        {
            TcpListener CurrentInterface = (TcpListener)result.AsyncState;
            InboundConnectionObject ClientConnection = new InboundConnectionObject(CurrentInterface.EndAcceptTcpClient(result),
                                                            this.ParentRelay.NetworkParameters.RxBufferSize);
            if (this.AcceptedPeers.Count <= this.ParentRelay.NetworkParameters.MaxPeers)
            {
                this.NotifyConnectionRequest(ClientConnection);
            }
            else
            {
                this.DenyPeeringRequest(ClientConnection);
            }
            this.NetworkInterface.BeginAcceptTcpClient(new AsyncCallback(this.ProcessConnectionRequest), this.NetworkInterface);
        }

        private void ProcessInboundMessage(IAsyncResult result)
        {
            InboundMessageObject container = (InboundMessageObject) result.AsyncState;
            int ReadBytesCount = container.client.client.Client.EndReceive(result);
            if(ReadBytesCount > 0)
            {
                container.MessageBuilder.Append(System.Text.Encoding.UTF8.GetString(container.client.buffer, 0, ReadBytesCount));
                container.client.ResetBufferState();
            }
            else if (container.MessageBuilder.Length > 0)
            {
                container.message = container.message.ToString();
                if(this.InboundMessageProcessors != null)
                {
                    this.InboundMessageProcessors(this, container);
                }
                container = new InboundMessageObject(container.client);
            }
            container.ReceiveAsync(new AsyncCallback(this.ProcessInboundMessage));
        }

        public void DenyPeeringRequest(InboundConnectionObject client)
        {
            client.Dispose();
        }

        public bool AcceptPeeringRequest(InboundConnectionObject client)
        {
            if(client.active && client.client.Connected)
            {
                this.AcceptedPeers.Add(client);
                client.client.Client.BeginReceive(client.buffer, 0, client.buffer.Length, SocketFlags.None, 
                    new AsyncCallback(this.ProcessInboundMessage), new InboundMessageObject(client));
                return true;
            }
            return false;
        }

        public void ReleasePeers()
        {
            InboundConnectionObject[] peers = this.AcceptedPeers.ToArray();
            foreach (InboundConnectionObject peer in peers)
            {
                peer.Dispose();
            }
            this.AcceptedPeers = new ConcurrentBag<InboundConnectionObject>();
        }

        public void Dispose()
        {
            this.BoundPort = 0;
            this.ReleasePeers();
            this.AcceptedPeers = null;
            this.NetworkInterface.Stop();
            this.PeeringRequestProcessors = null;
            this.InboundMessageProcessors = null;
        }

        public void StartAccepting()
        {
            this.NetworkInterface.Start(this.ParentRelay.NetworkParameters.MaxPeers);
            this.NetworkInterface.BeginAcceptTcpClient(new AsyncCallback(this.ProcessConnectionRequest), this.NetworkInterface);
        }

        public InboundInterface(Relay ParentRelay)
        {
            this.ParentRelay = ParentRelay;
            this.BoundPort = TORComm.Utilities.Network.GetUnusedPort();
            this.AcceptedPeers = new ConcurrentBag<InboundConnectionObject>();
            this.NetworkInterface = new TcpListener(TORComm.Active.CurrentAddress, this.BoundPort);
        }
    }

    public class OutboundInterface
    {
        private bool active;
        private int RemotePort;
        private String RemoteAddress;

        private TcpClient Connection;
        private ConcurrentQueue<String> OutboundMessageQueue;

        private bool TransmitString(String message)
        {
            bool TransmissionSuccessful = false;
            try
            {
                Byte[] OutboundBuffer = System.Text.Encoding.UTF8.GetBytes(message);
                Connection.Client.Send(OutboundBuffer, SocketFlags.None);
                TransmissionSuccessful = true;
            }
            catch (SocketException)
            {
                // Return failure on socket exception
                TransmissionSuccessful = false;
            }
            catch
            {
                // Throw anything else higher so we can see it
                throw;
            }
            return TransmissionSuccessful;
        }

        private void TransmissionThread()
        {
            while(active)
            {
                if(this.Connection.Client.Connected)
                {
                    if(this.OutboundMessageQueue.Count > 0)
                    {
                        String message = String.Empty;
                        bool DequeueSuccessful = false;
                        while(!(DequeueSuccessful))
                        {
                            DequeueSuccessful = this.OutboundMessageQueue.TryDequeue(out message);
                        }
                        bool TransmissionSuccessful = TransmitString(message);
                        if(!(TransmissionSuccessful))
                        {
                            // Delay and retry
                            this.OutboundMessageQueue.Enqueue(message);
                            Thread.Sleep(500);
                        }
                    }
                    else
                    {
                        // Wait for a message
                        Thread.Sleep(250);
                    }
                }
                else
                {
                    // Wait for a connection
                    Thread.Sleep(250);
                }
            }
        } 

        public void SendMessage(String message)
        {
            this.OutboundMessageQueue.Enqueue(message);
        }

        public bool ConnectTo(PeerAddressObject client)
        {
            if(!(String.IsNullOrEmpty(client.NetworkAddress)) && (client.NetworkPort > 0 && client.NetworkPort < 65536))
            {
                this.Connection.Connect(client.NetworkAddress, client.NetworkPort);
                return this.Connection.Connected;
            }
            return false;
        }
    }
}