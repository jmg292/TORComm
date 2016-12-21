using System;
using System.Threading;
using System.Net.Sockets;

namespace TORComm.Network.Abstract
{
    public delegate void MessageReceivedEventHander(Object sender, EventArgs e);

    public interface ISocketInterface
    {
        event MessageReceivedEventHander MessageReceived;
        void Dispose();
        bool IsConnected();
        int Send(Byte[] Message);
        IStreamInterface GetStream();
        void StopNotifyMessageReceived();
        void StartNotifyMessageReceived();
        IAsyncResult BeginReceive(Byte[] buffer, int index, int buffersize, SocketFlags flags, AsyncCallback function, Object OutputObject);
    }

    public interface IStreamInterface
    {
        event MessageReceivedEventHander MessageReceived;
        int ReadByte();
        void Dispose();
        bool DataAvailable();
        void StopNotifyMessageReceived();
        void StartNotifyMessageReceived();
        void Write(Byte[] Message, int index, int length);
    }

    public class WrappedSocket : ISocketInterface
    {
        private Thread NotifyThread;
        private bool NotifyThreadActive;
        private bool NotifiedDataAvailable;

        public Socket UnderlyingSocket;
        public event MessageReceivedEventHander MessageReceived;

        private void NotifyMessageReceived()
        {
            while (this.NotifyThreadActive)
            {
                if (this.UnderlyingSocket.Available > 0)
                {
                    if ((!(this.NotifiedDataAvailable)) && (this.MessageReceived != null))
                    {
                        MessageReceived(this, EventArgs.Empty);
                        this.NotifiedDataAvailable = true;
                    }
                }
                Thread.Sleep(500);
            }
        }

        public void Dispose()
        {
            this.UnderlyingSocket.Dispose();
        }

        public bool IsConnected()
        {
            return this.UnderlyingSocket.Connected;
        }

        public int Send(Byte[] Message)
        {
            return this.UnderlyingSocket.Send(Message);
        }

        public void StartNotifyMessageReceived()
        {
            this.NotifyThreadActive = true;
            this.NotifyThread.Start();
        }

        public void StopNotifyMessageReceived()
        {
            if (this.NotifyThreadActive)
            {
                this.NotifyThreadActive = false;
                this.NotifyThread.Join();
            }
        }

        public IStreamInterface GetStream()
        {
            return new WrappedNetworkStream(new NetworkStream(this.UnderlyingSocket));
        }

        public IAsyncResult BeginReceive(Byte[] buffer, int offset, int size, SocketFlags flags, AsyncCallback callback, Object state)
        {
            IAsyncResult result = this.UnderlyingSocket.BeginReceive(buffer, offset, size, flags, callback, state);
            this.NotifiedDataAvailable = false;
            return result;
        }

        public WrappedSocket(Socket s)
        {
            this.UnderlyingSocket = s;
            this.NotifiedDataAvailable = false;
            this.NotifyThread = new Thread(new ThreadStart(this.NotifyMessageReceived));
        }
    }

    public class WrappedNetworkStream : IStreamInterface
    {
        private Thread NotifyThread;
        private bool NotifyThreadActive;
        private bool NotifiedDataAvailable;

        public NetworkStream UnderlyingStream;
        public event MessageReceivedEventHander MessageReceived;

        private void NotifyMessageReceived()
        {
            while (this.NotifyThreadActive)
            {
                if (this.UnderlyingStream.DataAvailable)
                {
                    if ((!(this.NotifiedDataAvailable)) && (this.MessageReceived != null))
                    {
                        MessageReceived(this, EventArgs.Empty);
                        this.NotifiedDataAvailable = true;
                    }
                }
                Thread.Sleep(500);
            }
        }

        public void Dispose()
        {
            this.StopNotifyMessageReceived();
            this.UnderlyingStream.Dispose();
        }

        public void StartNotifyMessageReceived()
        {
            this.NotifyThreadActive = true;
            this.NotifyThread.Start();
        }

        public void StopNotifyMessageReceived()
        {
            if (this.NotifyThreadActive)
            {
                this.NotifyThreadActive = false;
                this.NotifyThread.Join();
            }
        }

        public bool DataAvailable()
        {
            return this.UnderlyingStream.DataAvailable;
        }

        public int ReadByte()
        {
            this.NotifiedDataAvailable = false;
            return this.UnderlyingStream.ReadByte();
        }

        public void Write(Byte[] Message, int offset, int length)
        {
            this.UnderlyingStream.Write(Message, offset, length);
        }

        public WrappedNetworkStream(NetworkStream s)
        {
            this.UnderlyingStream = s;
            this.NotifyThreadActive = false;
            this.NotifyThread = new Thread(new ThreadStart(this.NotifyMessageReceived));
        }
    }
}