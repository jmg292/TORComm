using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace TORComm.Network
{
    public class TransportProtocol
    {
        public bool IsSecured;
        public bool IsConnected;
        public String ServiceAddress;
        
        public TORComm.Components.Network.ConnectionMode MODE;
        public TORComm.Network.Abstract.ISocketInterface ConnectedSocket;
        public TORComm.Network.Abstract.IStreamInterface ConnectionStream;
        
        private TcpClient ClientConnection;
        private TcpListener ServerConnection;

        private Thread InboundQueueManager;
        private Thread OutboundQueueManager;
        private ConcurrentQueue<String> InboundQueue;
        private ConcurrentQueue<String> OutboundQueue;

        private TORComm.Security.KeyFactory KeyFactory;
        private TORComm.Components.Network.SessionParameterObject SessionParameters;

        private void InboundWatcherThread()
        {
            while (this.IsConnected)
            {
                if (this.ConnectionStream.DataAvailable())
                {
                    String DecryptedMessage = String.Empty;
                    using (MemoryStream mstream = new MemoryStream())
                    {
                        using (BinaryWriter writer = new BinaryWriter(mstream))
                        {
                            try
                            {
                                while (this.ConnectionStream.DataAvailable())
                                {
                                    int ReadByte = this.ConnectionStream.ReadByte();
                                    if (ReadByte != -1)
                                    {
                                        writer.Write((byte)ReadByte);
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                            }
                            catch (System.Exception ex)
                            {
                                if (ex is SocketException || ex is ObjectDisposedException || ex is IOException)
                                {
                                    Thread t = new Thread(new ThreadStart(this.Disconnect));
                                    t.Start();
                                    return;
                                }
                                throw;
                            }
                        }
                        DecryptedMessage = this.DecryptMessage(mstream.ToArray());
                    }
                    if (!(String.IsNullOrEmpty(DecryptedMessage)))
                    {
                        this.InboundQueue.Enqueue(DecryptedMessage);
                    }
                }
                Thread.Sleep(100);
            }
        }

        private void OutboundWatcherThread()
        {
            while (this.IsConnected)
            {
                if (this.OutboundQueue.Count > 0)
                {
                    int timeout = 0;
                    int MaxTimeout = 0xFFFF;
                    bool DequeueSuccessful = false;
                    String OutboundMessage = String.Empty;
                    while ((!(DequeueSuccessful)) && (timeout < MaxTimeout))
                    {
                        DequeueSuccessful = this.OutboundQueue.TryDequeue(out OutboundMessage);
                    }
                    if (!(String.IsNullOrEmpty(OutboundMessage)))
                    {
                        try
                        {
                            Byte[] EncryptedMessage = this.EncryptMessage(OutboundMessage);
                            this.ConnectionStream.Write(EncryptedMessage, 0, EncryptedMessage.Length);
                        }
                        catch (System.Exception ex)
                        {
                            if (ex is SocketException || ex is ObjectDisposedException || ex is IOException)
                            {
                                Thread t = new Thread(new ThreadStart(this.Disconnect));
                                t.Start();
                                return;
                            }
                            throw;
                        }
                    }
                }
                Thread.Sleep(100);
            }
        }

        private void AsyncAcceptConnection(IAsyncResult result)
        {
            if (this.MODE == TORComm.Components.Network.ConnectionMode.SERVER)
            {
                this.ServerConnection = (TcpListener)result.AsyncState;
                this.ConnectedSocket = new Abstract.WrappedSocket(this.ServerConnection.EndAcceptSocket(result));
            }
            else if (this.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
            {
                this.ClientConnection = (TcpClient)result.AsyncState;
                this.ConnectedSocket = new Abstract.WrappedSocket(this.ClientConnection.Client);
                this.ClientConnection.EndConnect(result);
            }
            else
            {
                throw new System.InvalidOperationException("Unknown connection configuration, unable to process connection request.");
            }
            this.IsConnected = this.ConnectedSocket.IsConnected();
            if (this.IsConnected)
            {
                this.SessionParameters = new TORComm.Security.Handshake(this).PerformHandshakeSynchronously();
                this.KeyFactory.reseed(Convert.ToBase64String(this.SessionParameters.PrivateKeyObject.DeriveKeyMaterial(this.SessionParameters.PubKey)),
                                       this.SessionParameters.offset);
                this.ConnectionStream = this.ConnectedSocket.GetStream();
                this.IsSecured = this.SessionParameters.CompletedNoErrors;
                this.SessionParameters.PrivateKeyObject.Dispose();
                this.SessionParameters.PubKey.Dispose();
                this.OutboundQueueManager.Start();
                this.InboundQueueManager.Start();
            }
        }

        private Byte[] EncryptMessage(String message)
        {
            Byte[] EncryptedMessage = null;
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            if (this.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
            {
                aes.Key = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ClientKeyTrack);
                aes.IV = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ClientIVTrack, 128);
            }
            else
            {
                aes.Key = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ServerKeyTrack);
                aes.IV = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ServerIVTrack, 128);
            }
            using (MemoryStream mstream = new MemoryStream())
            {
                using (CryptoStream cstream = new CryptoStream(mstream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (BinaryWriter writer = new BinaryWriter(cstream))
                    {
                        writer.Write(System.Text.Encoding.UTF8.GetBytes(message));
                    }
                }
                EncryptedMessage = mstream.ToArray();
            }
            return EncryptedMessage;
        }

        private String DecryptMessage(Byte[] EncryptedMessage)
        {
            String DecryptedMessage = String.Empty;
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            if (this.MODE == TORComm.Components.Network.ConnectionMode.SERVER)
            {
                aes.Key = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ClientKeyTrack);
                aes.IV = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ClientIVTrack, 128);
            }
            else
            {
                aes.Key = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ServerKeyTrack);
                aes.IV = this.KeyFactory.GetKeyFromTrack(this.SessionParameters.ServerIVTrack, 128);
            }
            using (MemoryStream mstream = new MemoryStream())
            {
                using (CryptoStream cstream = new CryptoStream(mstream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    using (BinaryWriter writer = new BinaryWriter(cstream))
                    {
                        writer.Write(EncryptedMessage);
                    }
                }
                DecryptedMessage = System.Text.Encoding.UTF8.GetString(mstream.ToArray());
            }
            return DecryptedMessage;
        }

        public bool transmit(String message)
        {
            bool ReturnValue = false;
            if (this.IsConnected && this.IsSecured && (!(String.IsNullOrEmpty(message))))
            {
                this.OutboundQueue.Enqueue(message);
                ReturnValue = true;
            }
            return ReturnValue;
        }

        public String receive()
        {
            String ReturnValue = String.Empty;
            if (this.IsConnected && this.IsSecured && (this.InboundQueue.Count > 0))
            {
                bool DequeueSuccessful = false;
                while (!(DequeueSuccessful))
                {
                    DequeueSuccessful = this.InboundQueue.TryDequeue(out ReturnValue);
                }
            }
            return ReturnValue;
        }

        public void Disconnect()
        {
            if (this.IsConnected)
            {
                this.IsConnected = false;
                this.ConnectedSocket.Dispose();
                this.ConnectionStream.Dispose();
                if (this.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
                {
                    this.ClientConnection.Close();
                }
                else if (this.MODE == TORComm.Components.Network.ConnectionMode.SERVER)
                {
                    this.ServerConnection.Stop();
                }
                this.InboundQueueManager.Join();
                this.OutboundQueueManager.Join();
            }
        }

        public void Bind(int BindPort = 42790)
        {
            if (this.MODE == TORComm.Components.Network.ConnectionMode.SERVER)
            {
                IPAddress localaddr = Dns.GetHostAddresses(Dns.GetHostName()).First(a => a.AddressFamily == AddressFamily.InterNetwork);
                IPEndPoint BindPoint = new IPEndPoint(localaddr, BindPort);
                TcpListener BoundSocket = new TcpListener(BindPoint);
                BoundSocket.Start();
                this.ServiceAddress = String.Format("{0}:{1}", localaddr, BindPort);
                BoundSocket.BeginAcceptSocket(new AsyncCallback(this.AsyncAcceptConnection), BoundSocket);
            }
            else
            {
                throw new System.InvalidOperationException("Can't bind server.  REASON: Not a server.");
            }
        }

        public void Connect(String IpAddress, int PortNumber)
        {
            if (this.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
            {
                this.ClientConnection = new TcpClient();
                this.ClientConnection.BeginConnect(IpAddress, PortNumber, new AsyncCallback(this.AsyncAcceptConnection), this.ClientConnection);
            }
            else
            {
                throw new System.InvalidOperationException("Can't connect as client.  REASON: Not a client.");
            }
        }

        public void SetOperationalMode(TORComm.Components.Network.ConnectionMode NewMode)
        {
            if((!(this.IsConnected)) && (!(this.IsSecured)))
            {
                this.MODE = NewMode;
            }
            else
            {
                throw new System.InvalidOperationException("Attempted to change mode while already connected.");
            }
        }

        public TransportProtocol(TORComm.Components.Network.ConnectionMode OperationalMode = TORComm.Components.Network.ConnectionMode.CLIENT)
        {
            this.IsConnected = false;
            this.MODE = OperationalMode;
            this.ServiceAddress = String.Empty;
            this.InboundQueue = new ConcurrentQueue<string>();
            this.OutboundQueue = new ConcurrentQueue<string>();
            this.KeyFactory = new TORComm.Security.KeyFactory();
            this.InboundQueueManager = new Thread(new ThreadStart(this.InboundWatcherThread));
            this.OutboundQueueManager = new Thread(new ThreadStart(this.OutboundWatcherThread));
        }
    }
}