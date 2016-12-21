using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text;
using System.Numerics;
using System.Threading;
using System.Collections;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace TORComm.Security
{
    class KeyFactory
    {
        private ConcurrentDictionary<int, TORComm.Components.Security.KeySequenceObject> LocalState;

        private BigInteger GetFibonacciAtIndex(int index)
        {
            BigInteger a = 1, b = 1;
            for (int i = 0; i < index; i++)
            {
                BigInteger temp = a;
                a = b;
                b += temp;
            }
            return b;
        }

        private void IncrementAtIndex(int TrackIndex)
        {
            this.LocalState[TrackIndex].CurrentIndex += 1;
            if (!(this.LocalState[TrackIndex].IgnoreMaxIndex))
            {
                if (this.LocalState[TrackIndex].CurrentIndex >= 512)
                {
                    this.LocalState[TrackIndex].IgnoreMaxIndex = true;
                    String NextToken = Convert.ToBase64String(this.GetKeyFromTrack(TrackIndex, 512));
                    this.LocalState[TrackIndex].CurrentIndex = 0;
                    this.LocalState[TrackIndex].KeyToken = NextToken;
                    this.LocalState[TrackIndex].IgnoreMaxIndex = false;
                }
            }
        }

        public void reseed(String vector, int offset = 0)
        {
            HMACSHA512 hmac = new HMACSHA512();
            hmac.Key = System.Text.Encoding.UTF8.GetBytes(vector);
            for (int i = 0; i < 256; i++)
            {
                TORComm.Components.Security.KeySequenceObject KeySequence = new Components.Security.KeySequenceObject();
                BigInteger FibonacciAtIndex = this.GetFibonacciAtIndex(i + offset);
                KeySequence.KeyToken = Convert.ToBase64String(hmac.ComputeHash(FibonacciAtIndex.ToByteArray()));
                KeySequence.SequenceOffset = ((i + offset) % 256);
                bool AddSuccess = false;
                while (!(AddSuccess))
                {
                    AddSuccess = this.LocalState.TryAdd(i, KeySequence);
                }
            }
            hmac.Dispose();
        }

        public String GetNextFromTrack(int TrackIndex)
        {
            TrackIndex %= 255;
            String ReturnValue = String.Empty;
            if (this.LocalState.ContainsKey(TrackIndex))
            {
                HMACSHA512 hmac = new HMACSHA512();
                hmac.Key = Convert.FromBase64String(this.LocalState[TrackIndex].KeyToken);
                BigInteger DigestToken = this.GetFibonacciAtIndex(this.LocalState[TrackIndex].CurrentIndex);
                ReturnValue = Convert.ToBase64String(hmac.ComputeHash(DigestToken.ToByteArray())).Replace("=", "");
                this.IncrementAtIndex(TrackIndex);
                hmac.Dispose();
            }
            else
            {
                throw new System.InvalidOperationException(String.Format("Index {0} not found.  Has the key generator been seeded?", TrackIndex));
            }
            return ReturnValue;
        }

        public Byte[] GetKeyFromTrack(int TrackIndex, int KeySize = 256)
        {
            if (KeySize > 512)
            {
                throw new InvalidOperationException("Requested key size is too large.");
            }
            KeySize /= 8; int index = 0;
            ArrayList intermediary = new ArrayList();
            String KeyString = this.GetNextFromTrack(TrackIndex);
            if (String.IsNullOrEmpty(KeyString))
            {
                throw new InvalidOperationException("Requested key sequence is null.  Has the generator been seeded?");
            }
            SHA512CryptoServiceProvider sha = new SHA512CryptoServiceProvider();
            Byte[] KeyByteArray = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(KeyString));
            while (!(intermediary.Count == KeySize))
            {
                intermediary.Add(KeyByteArray[index++]);
            }
            return (Byte[])intermediary.ToArray(typeof(byte));
        }

        public KeyFactory()
        {
            this.LocalState = new ConcurrentDictionary<int, TORComm.Components.Security.KeySequenceObject>();
        }
    }

    class Handshake
    {
        private int AcknowledgementNonce;
        private ECDiffieHellmanCng AckKeyPair;
        private AesCryptoServiceProvider SessionCrypto;

        public TORComm.Network.TransportProtocol CurrentTransport;
        public TORComm.Components.Network.SessionParameterObject parameters;
        public TORComm.Components.Security.HandshakeInformation.HandshakeStage CurrentStage;

        private void transmit(Byte[] message)
        {
            try
            {
                int TransmittedByteCount = 0;
                while (TransmittedByteCount < message.Count())
                {
                    TransmittedByteCount = this.CurrentTransport.ConnectedSocket.Send(message);
                }
            }
            catch (System.Exception ex)
            {
                if (ex is SocketException || ex is ObjectDisposedException || ex is IOException)
                {
                    this.TerminateSession();
                    return;
                }
                throw;
            }
        }

        private void TerminateSession(IAsyncResult result = null)
        {
            this.AckKeyPair.Dispose();
            this.SessionCrypto.Dispose();
            this.AcknowledgementNonce = 0;
            this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.DONE;
        }

        private byte[] EncryptMessage(String message)
        {
            this.SessionCrypto.GenerateIV();
            ArrayList intermediary = new ArrayList();
            intermediary.AddRange(this.SessionCrypto.IV);
            using (MemoryStream mstream = new MemoryStream())
            {
                using (CryptoStream cstream = new CryptoStream(mstream, this.SessionCrypto.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (BinaryWriter writer = new BinaryWriter(cstream))
                    {
                        writer.Write(System.Text.Encoding.UTF8.GetBytes(message));
                    }
                }
                intermediary.AddRange(mstream.ToArray());
            }
            return (Byte[])intermediary.ToArray(typeof(byte));
        }

        private String DecryptMessage(Byte[] message)
        {
            String ReturnValue = String.Empty;
            ArrayList intermediary = new ArrayList();
            for (int i = 0; i < 16; i++)
            {
                intermediary.Add(message[i]);
            }
            this.SessionCrypto.IV = (Byte[])intermediary.ToArray(typeof(byte));
            using (MemoryStream mstream = new MemoryStream())
            {
                using (CryptoStream cstream = new CryptoStream(mstream, this.SessionCrypto.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    using (BinaryWriter writer = new BinaryWriter(cstream))
                    {
                        writer.Write(message.Skip(16).ToArray());
                    }
                }
                ReturnValue = System.Text.Encoding.UTF8.GetString(mstream.ToArray());
            }
            return ReturnValue;
        }

        private bool ValidateHeader(Byte[] RxMessage, TORComm.Components.Security.HandshakeInformation.HandshakeStage ExpectedState)
        {
            ArrayList ConversionArray = new ArrayList();
            for (int i = 0; i < 4; i++)
            {
                ConversionArray.Add(RxMessage[i]);
            }
            int CurrentState = BitConverter.ToInt32((Byte[])ConversionArray.ToArray(typeof(byte)), 0);
            if (CurrentState == (Int32)ExpectedState)
            {
                return true;
            }
            return false;
        }

        private String CreateToken(ECDiffieHellmanCngPublicKey PubKey, int offset, int ClientKeyTrack, int ClientIVTrack,
                           int ServerKeyTrack, int ServerIVTrack)
        {
            StringBuilder TokenBuilder = new StringBuilder();
            foreach (Byte b in PubKey.ToByteArray())
            {
                TokenBuilder.Append(b.ToString("X2"));
            }
            TokenBuilder.Append(offset.ToString("X4"));
            TokenBuilder.Append(ServerKeyTrack.ToString("X2"));
            TokenBuilder.Append(ServerIVTrack.ToString("X2"));
            TokenBuilder.Append(ClientKeyTrack.ToString("X2"));
            TokenBuilder.Append(ClientIVTrack.ToString("X2"));
            return TokenBuilder.ToString();
        }

        private TORComm.Components.Network.SessionParameterObject LoadToken(String token, TORComm.Components.Network.SessionParameterObject SessionParams)
        {
            String PubKeyString = token.Substring(0, token.Length - 12);
            String ParameterString = token.Substring(token.Length - 12);
            SessionParams.PubKey = (ECDiffieHellmanCngPublicKey)ECDiffieHellmanCngPublicKey.FromByteArray((Byte[])Enumerable.Range(0, PubKeyString.Length / 2)
                                                 .Select(x => Convert.ToByte(PubKeyString.Substring(x * 2, 2), 16)).ToArray(), new CngKeyBlobFormat("ECCPUBLICBLOB"));
            SessionParams.offset = Convert.ToInt32(ParameterString.Substring(0, 4), 16);
            SessionParams.ServerKeyTrack = Convert.ToInt32(ParameterString.Substring(4, 2), 16);
            SessionParams.ServerIVTrack = Convert.ToInt32(ParameterString.Substring(6, 2), 16);
            SessionParams.ClientKeyTrack = Convert.ToInt32(ParameterString.Substring(8, 2), 16);
            SessionParams.ClientIVTrack = Convert.ToInt32(ParameterString.Substring(10, 2), 16);
            return SessionParams;
        }

        private void EndTransmission(IAsyncResult result)
        {
            Byte[] RxBuffer = (Byte[])result.AsyncState;
            Byte[] RxMessage = new Byte[320];
            Array.Copy(RxBuffer.Skip(4).ToArray(), RxMessage, RxMessage.Length);
            if (this.ValidateHeader(RxBuffer, TORComm.Components.Security.HandshakeInformation.HandshakeStage.EOT))
            {
                ArrayList TxArray = new ArrayList();
                String SessionToken = this.DecryptMessage(RxMessage);
                if (!(SessionToken.Length == 292))
                {
                    throw new ProtocolViolationException(String.Format("Expecting 292 bytes but received {0} bytes.  Invalid session token received.", SessionToken.Length));
                }
                else
                {
                    if (this.CurrentTransport.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
                    {
                        this.parameters = new TORComm.Components.Network.SessionParameterObject();
                        this.parameters.PrivateKeyObject = new ECDiffieHellmanCng();
                        this.parameters = this.LoadToken(SessionToken, this.parameters);
                        TxArray.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.EOT));
                        String ResponseToken = this.CreateToken((ECDiffieHellmanCngPublicKey)this.parameters.PrivateKeyObject.PublicKey, this.parameters.offset,
                                                                this.parameters.ClientKeyTrack, this.parameters.ClientIVTrack, this.parameters.ServerKeyTrack, this.parameters.ServerIVTrack);
                        TxArray.AddRange(this.EncryptMessage(ResponseToken));
                        this.parameters.CompletedNoErrors = true;
                    }
                    else
                    {
                        this.parameters = this.LoadToken(SessionToken, this.parameters);
                        this.parameters.CompletedNoErrors = true;
                    }
                    if (TxArray.Count > 0)
                    {
                        this.transmit((Byte[])TxArray.ToArray(typeof(byte)));
                    }
                    this.TerminateSession();
                }
            }
        }

        private void SynchronizeConnection(IAsyncResult result)
        {
            Byte[] RxBuffer = (Byte[])result.AsyncState;
            if (this.ValidateHeader(RxBuffer, TORComm.Components.Security.HandshakeInformation.HandshakeStage.SYN))
            {
                ArrayList TxArray = new ArrayList();
                if (this.CurrentTransport.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
                {
                    ArrayList TrucateArray = new ArrayList();
                    foreach (byte b in RxBuffer.Skip(4).ToArray())
                    {
                        if (Convert.ToInt32(b) != 0)
                        {
                            TrucateArray.Add(b);
                        }
                    }
                    Byte[] RxMessage = (Byte[])TrucateArray.ToArray(typeof(byte));
                    TxArray.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.SYN));
                    TxArray.AddRange(this.EncryptMessage(System.Text.Encoding.UTF8.GetString(RxMessage)));
                }
                else
                {
                    Byte[] RxMessage = new Byte[32];
                    Array.Copy(RxBuffer.Skip(4).ToArray(), RxMessage, RxMessage.Length);
                    int ReceivedNonce = Convert.ToInt32(this.DecryptMessage(RxMessage));
                    if (ReceivedNonce == this.AcknowledgementNonce)
                    {
                        this.parameters.PrivateKeyObject = new ECDiffieHellmanCng();
                        this.parameters.offset = TORComm.Utilities.Security.GetRandomInt(4096);
                        this.parameters.ServerKeyTrack = TORComm.Utilities.Security.GetRandomInt(255);
                        this.parameters.ServerIVTrack = this.parameters.ClientKeyTrack = this.parameters.ClientIVTrack = parameters.ServerKeyTrack;
                        while (this.parameters.ServerKeyTrack == this.parameters.ServerIVTrack)
                        {
                            this.parameters.ServerIVTrack = TORComm.Utilities.Security.GetRandomInt(255);
                        }
                        while (this.parameters.ClientKeyTrack == this.parameters.ServerKeyTrack || this.parameters.ClientKeyTrack == this.parameters.ServerIVTrack)
                        {
                            this.parameters.ClientKeyTrack = TORComm.Utilities.Security.GetRandomInt(255);
                        }
                        while (this.parameters.ClientIVTrack == this.parameters.ServerKeyTrack || this.parameters.ClientIVTrack == this.parameters.ServerIVTrack || this.parameters.ClientIVTrack == this.parameters.ClientKeyTrack)
                        {
                            this.parameters.ClientIVTrack = TORComm.Utilities.Security.GetRandomInt(255);
                        }
                        TxArray.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.EOT));
                        String SessionToken = this.CreateToken((ECDiffieHellmanCngPublicKey)this.parameters.PrivateKeyObject.PublicKey, this.parameters.offset,
                                                               this.parameters.ClientKeyTrack, this.parameters.ClientIVTrack, this.parameters.ServerKeyTrack, this.parameters.ServerIVTrack);
                        TxArray.AddRange(this.EncryptMessage(SessionToken));
                    }
                    else
                    {
                        TxArray.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.NACK));
                        this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.NACK;
                        this.transmit((Byte[])TxArray.ToArray(typeof(byte)));
                        this.WaitForNextMessage();
                    }
                }
                this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.EOT;
                this.transmit((Byte[])TxArray.ToArray(typeof(byte)));
                this.WaitForNextMessage();
            }
            else
            {
                throw new ProtocolViolationException("Invalid SYN header received.");
            }
        }

        private void RecieveAcknowledgement(IAsyncResult result)
        {
            Byte[] RxBuffer = (Byte[])result.AsyncState;
            Byte[] RxMessage = new Byte[140];
            Array.Copy(RxBuffer.Skip(4).ToArray(), RxMessage, RxMessage.Length);
            if (this.ValidateHeader(RxBuffer, TORComm.Components.Security.HandshakeInformation.HandshakeStage.ACK))
            {
                ArrayList TempArrayList = new ArrayList();
                ECDiffieHellmanCngPublicKey PubKey = (ECDiffieHellmanCngPublicKey)ECDiffieHellmanCngPublicKey.FromByteArray(RxMessage, new CngKeyBlobFormat("ECCPUBLICBLOB"));
                if (this.CurrentTransport.MODE == TORComm.Components.Network.ConnectionMode.CLIENT)
                {
                    this.AckKeyPair = new ECDiffieHellmanCng();
                    TempArrayList.AddRange(BitConverter.GetBytes((int)TORComm.Components.Security.HandshakeInformation.HandshakeStage.ACK));
                    TempArrayList.AddRange(this.AckKeyPair.PublicKey.ToByteArray());
                }
                this.SessionCrypto.Key = this.AckKeyPair.DeriveKeyMaterial(PubKey);
                PubKey.Dispose();
                if (this.CurrentTransport.MODE == TORComm.Components.Network.ConnectionMode.SERVER)
                {
                    this.AcknowledgementNonce = Convert.ToInt32(TORComm.Utilities.Security.GetRandomInt().ToString().TrimEnd('0'));
                    TempArrayList.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.SYN));
                    TempArrayList.AddRange(System.Text.Encoding.UTF8.GetBytes(this.AcknowledgementNonce.ToString()));
                }
                this.transmit((Byte[])TempArrayList.ToArray(typeof(byte)));
                this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.SYN;
                this.WaitForNextMessage();
            }
            else
            {
                throw new ProtocolViolationException("Invalid ACK header received.");
            }
        }

        private void associate(IAsyncResult result = null)
        {
            if (this.CurrentTransport.IsConnected)
            {
                ArrayList MessageContainer = new ArrayList();
                MessageContainer.AddRange(TORComm.Components.Security.HandshakeInformation.header);
                MessageContainer.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.ASSOC));
                Byte[] AssociateMessage = (Byte[])MessageContainer.ToArray(typeof(byte));
                if (this.CurrentTransport.MODE == TORComm.Components.Network.ConnectionMode.SERVER)
                {
                    if (!(result == null))
                    {
                        Byte[] RxBuffer = (Byte[])result.AsyncState;
                        Byte[] ProcessedBuffer = new byte[AssociateMessage.Length];
                        Array.Copy(RxBuffer, ProcessedBuffer, ProcessedBuffer.Length);
                        if (AssociateMessage.SequenceEqual(ProcessedBuffer))
                        {
                            MessageContainer = new ArrayList();
                            this.AckKeyPair = new ECDiffieHellmanCng();
                            MessageContainer.AddRange(BitConverter.GetBytes((Int32)TORComm.Components.Security.HandshakeInformation.HandshakeStage.ACK));
                            MessageContainer.AddRange(this.AckKeyPair.PublicKey.ToByteArray());
                            AssociateMessage = (Byte[])MessageContainer.ToArray(typeof(byte));
                        }
                        else
                        {
                            throw new ProtocolViolationException("Invalid SYN message supplied.");
                        }
                    }
                    else
                    {
                        throw new ArgumentNullException("Expected client message, but RX Buffer is null.");
                    }
                }
                this.transmit(AssociateMessage);
                this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.ACK;
                this.WaitForNextMessage();
            }
            else
            {
                throw new SocketException();
            }
        }

        private void WaitForNextMessage()
        {
            AsyncCallback CallbackFunction = null;
            switch (this.CurrentStage)
            {
                case TORComm.Components.Security.HandshakeInformation.HandshakeStage.ASSOC:
                    CallbackFunction = new AsyncCallback(this.associate);
                    break;

                case TORComm.Components.Security.HandshakeInformation.HandshakeStage.ACK:
                    CallbackFunction = new AsyncCallback(this.RecieveAcknowledgement);
                    break;

                case TORComm.Components.Security.HandshakeInformation.HandshakeStage.SYN:
                    CallbackFunction = new AsyncCallback(this.SynchronizeConnection);
                    break;

                case TORComm.Components.Security.HandshakeInformation.HandshakeStage.NACK:
                    CallbackFunction = new AsyncCallback(this.TerminateSession);
                    break;

                case TORComm.Components.Security.HandshakeInformation.HandshakeStage.EOT:
                    CallbackFunction = new AsyncCallback(this.EndTransmission);
                    break;
            }
            if ((this.CurrentTransport.MODE == TORComm.Components.Network.ConnectionMode.CLIENT) && 
                (this.CurrentStage == TORComm.Components.Security.HandshakeInformation.HandshakeStage.ASSOC))
            {
                this.associate();
            }
            else
            {
                Byte[] RxBuffer = new Byte[4096];
                this.CurrentTransport.ConnectedSocket.BeginReceive(RxBuffer, 0, 4096, SocketFlags.None, CallbackFunction, RxBuffer);
            }
        }

        public TORComm.Components.Network.SessionParameterObject PerformHandshakeSynchronously()
        {
            this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.ASSOC;
            this.WaitForNextMessage();
            while (!(this.CurrentStage == TORComm.Components.Security.HandshakeInformation.HandshakeStage.DONE))
            {
                Thread.Sleep(500);
            }
            return this.parameters;
        }

        public Handshake(TORComm.Network.TransportProtocol CurrentTransport)
        {
            this.CurrentTransport = CurrentTransport;
            this.AckKeyPair = new ECDiffieHellmanCng();
            this.SessionCrypto = new AesCryptoServiceProvider();
            this.parameters = new TORComm.Components.Network.SessionParameterObject();
            this.CurrentStage = TORComm.Components.Security.HandshakeInformation.HandshakeStage.ASSOC;
        }
    }

    public static class MessageValidation
    {
        public static bool HMACIsValid(String MessageString, String KeyString)
        {
            bool IsValid = false;
            if (MessageString.Length > 32)
            {
                HMACSHA512 hmac = new HMACSHA512();
                hmac.Key = System.Text.Encoding.UTF8.GetBytes(KeyString);
                Byte[] ProvidedHmac = System.Text.Encoding.UTF8.GetBytes(MessageString.Substring(0, 32));
                Byte[] Derivedhmac = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(MessageString.Substring(31)));
                if (ProvidedHmac == Derivedhmac)
                {
                    IsValid = true;
                }
            }
            return IsValid;
        }

        public static String PrependHMAC(String MessageString, String KeyString)
        {
            HMACSHA512 hmac = new HMACSHA512();
            hmac.Key = System.Text.Encoding.UTF8.GetBytes(KeyString);
            return System.Text.Encoding.UTF8.GetString(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(MessageString))) + MessageString;
        }
    }
}