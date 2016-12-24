using System;
using System.Threading;
using System.Collections;
using System.Collections.Generic;

namespace TORComm.Network
{
    public class HiddenServiceHandler
    {
        private int ResetValue;
        private int TimeoutCounter;
        private int DescriptorCount;
        private String OnionAddress;
        private Thread TimeoutThread;
        private bool DescriptorFetchCompleted;
        private TORComm.Components.Network.RendezvousDescriptorObject RendezvousDescriptor;
        private static String[] RequiredEventSubscriptions = new String[] { "HS_DESC", "HS_DESC_CONTENT" };

        private void SubscribeToEventHandler()
        {
            TORComm.Active.CommandInterface.NotifyAsyncMessageReceived += this.AsyncResponseHandler;
        }

        private void UnsubscribeOnTimeout()
        {
            this.ResetTimeout();
            while(TimeoutCounter != 0)
            {
                Thread.Sleep(1000);
                this.TimeoutCounter -= 1;
            }
            TORComm.Active.CommandInterface.NotifyAsyncMessageReceived -= this.AsyncResponseHandler;
            this.DescriptorFetchCompleted = true;
        }

        private void ResetTimeout()
        {
            this.TimeoutCounter = this.ResetValue;
        }

        private void AsyncResponseHandler(Object sender, TORComm.Components.Network.AsyncResponseObject ResponseObject)
        {
            if (TORComm.Active.CommandInterface.AsyncResponseOK(ResponseObject.ProcessedResponse))
            {
                bool MessageIsHSDescriptor = false;
                foreach (String EventCode in RequiredEventSubscriptions)
                {
                    MessageIsHSDescriptor |= ResponseObject.ProcessedResponse.Contains(EventCode);
                }
                if(MessageIsHSDescriptor)
                {
                    if(ResponseObject.ProcessedResponse.Contains(this.OnionAddress))
                    {
                        this.DescriptorCount++;
                        this.ResetTimeout();
                    }
                }
            }                 
        }

        private TORComm.Components.Network.IntroductionPointObject[] LoadIntroductionPoints(String EncodedMessage)
        {
            ArrayList IntroPoints = new ArrayList();
            TORComm.Components.Network.IntroductionPointObject CurrentIntroPoint = null;
            String[] DecodedMessage = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(EncodedMessage)).Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None);
            for(int i = 0; i < DecodedMessage.Length; i++)
            {                
                if(DecodedMessage[i].StartsWith("introduction-point"))
                {
                    if(CurrentIntroPoint != null)
                    {
                        if(CurrentIntroPoint.router != null)
                        {
                            IntroPoints.Add(CurrentIntroPoint);
                        }
                    }
                    CurrentIntroPoint = new Components.Network.IntroductionPointObject();
                    CurrentIntroPoint.identity = DecodedMessage[i].Split(' ')[1];
                }
                else if (DecodedMessage[i].StartsWith("ip-address"))
                {
                    CurrentIntroPoint.router = TORComm.Network.RouterManagement.GetRouterByAddress(DecodedMessage[i].Split(' ')[1]);
                }
                else if (DecodedMessage[i].StartsWith("onion-key"))
                {
                    TORComm.Components.Security.KeyConversionAssistant ConversionHelper = TORComm.Security.RSA.Extract.KeyFromArray(i, DecodedMessage);
                    if(ConversionHelper.ConvertedKey != null)
                    {
                        CurrentIntroPoint.PublicKey = ConversionHelper.ConvertedKey;
                    }
                    i = ConversionHelper.index;
                }
                else if (DecodedMessage[i].StartsWith("service-key") && this.RendezvousDescriptor.ServicePublicKey == null)
                {
                    TORComm.Components.Security.KeyConversionAssistant ConversionHelper = TORComm.Security.RSA.Extract.KeyFromArray(i, DecodedMessage);
                    if (ConversionHelper.ConvertedKey != null)
                    {
                        this.RendezvousDescriptor.ServicePublicKey = ConversionHelper.ConvertedKey;
                    }
                    i = ConversionHelper.index;
                }
                else
                {
                    continue;
                }
            }
            return (TORComm.Components.Network.IntroductionPointObject[])IntroPoints.ToArray(typeof(TORComm.Components.Network.IntroductionPointObject));
        }

        private void LoadRendezvousDescriptor(String DescriptorString)
        {
            this.RendezvousDescriptor = new TORComm.Components.Network.RendezvousDescriptorObject();
            String[] SplitDescriptor = DescriptorString.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None);
            for(int i = 0; i < SplitDescriptor.Length; i++)
            {
                String NextDescriptorPart = SplitDescriptor[i];
                if(NextDescriptorPart.StartsWith("rendezvous-service-descriptor"))
                {
                    this.RendezvousDescriptor.identity = NextDescriptorPart.Split(' ')[1];
                }
                else if (NextDescriptorPart.StartsWith("version"))
                {
                    this.RendezvousDescriptor.DescriptorVersion = Int32.Parse(NextDescriptorPart.Split(' ')[1]);
                }
                else if (NextDescriptorPart.StartsWith("permanent-key"))
                {
                    TORComm.Components.Security.KeyConversionAssistant ConversionHelper = TORComm.Security.RSA.Extract.KeyFromArray(i, SplitDescriptor);
                    if (ConversionHelper.ConvertedKey != null)
                    {
                        this.RendezvousDescriptor.PermanentPublicKey = ConversionHelper.ConvertedKey;
                    }
                    i = ConversionHelper.index;
                }
                else if (NextDescriptorPart.StartsWith("secret-id-part"))
                {
                    this.RendezvousDescriptor.SecretIdentity = NextDescriptorPart.Split(' ')[1];
                }
                else if (NextDescriptorPart.StartsWith("publication-time"))
                {
                    this.RendezvousDescriptor.PublicationTime = DateTime.Parse(NextDescriptorPart.Split(' ')[1]);
                }
                else if (NextDescriptorPart.StartsWith("protocol-versions"))
                {
                    List<int> ProtocolVersionList = new List<int>();
                    foreach(String VersionNumber in NextDescriptorPart.Split(' ')[1].Split(','))
                    {
                        int ParsedVersionNumber = 0;
                        if(Int32.TryParse(VersionNumber, out ParsedVersionNumber))
                        {
                            ProtocolVersionList.Add(ParsedVersionNumber);
                        }
                    }
                    this.RendezvousDescriptor.ProtocolVersions = ProtocolVersionList.ToArray();
                }
                else if (NextDescriptorPart.StartsWith("introduction-points"))
                {
                    i += 2;
                    List<String> MessageContents = new List<string>();
                    while(!(SplitDescriptor[i].Contains("END MESSAGE")))
                    {
                        MessageContents.Add(SplitDescriptor[i++]);
                    }
                    this.RendezvousDescriptor.AdvertisedIntroPoints = this.LoadIntroductionPoints(String.Join(String.Empty, MessageContents.ToArray()));
                }
                else if (NextDescriptorPart.StartsWith("signature"))
                {
                    // TODO: Once everything else is confirmed working, implement signature validation
                    continue;
                }
                else
                {
                    continue;
                }
            }
        }

        private bool RetrieveAndLoadRendezvousDescriptor()
        {
            this.DescriptorCount = 0;
            this.TimeoutThread.Start();
            this.SubscribeToEventHandler();
            String CmdResponse = TORComm.Active.CommandInterface.SendCommand(String.Format("HSFETCH {0}", OnionAddress));
            if(TORComm.Active.CommandInterface.ResponseOK(CmdResponse))
            {
                Console.WriteLine("[+] Caching hidden service descriptors, this will take a moment.");
                while (!(this.DescriptorFetchCompleted))
                {
                    Thread.Sleep(500);
                }
                if(this.DescriptorFetchCompleted && this.DescriptorCount > 0)
                {
                    Console.WriteLine("[+] Service descriptors cached, retrieving rendezvous descriptor.");
                    CmdResponse = TORComm.Active.CommandInterface.SendCommand(String.Format("GETINFO hs/service/desc/id/{0}", this.OnionAddress));
                    if(TORComm.Active.CommandInterface.ResponseOK(CmdResponse))
                    {
                        Console.Write("[+] Rendezvous descriptor retrieved successfully, loading... ");
                        this.LoadRendezvousDescriptor(CmdResponse);
                        Console.WriteLine("Done.\n[+] Rendezvous descriptor loaded.  Results:\n");
                        Console.WriteLine("\t+ ID: {0}", this.RendezvousDescriptor.identity);
                        Console.WriteLine("\t+ Secret ID Part: {0}", this.RendezvousDescriptor.SecretIdentity);
                        Console.WriteLine("\t+ Descriptor version: {0}", this.RendezvousDescriptor.DescriptorVersion);
                        Console.WriteLine("\t+ Supported protocol versions: {0}", String.Join(",", this.RendezvousDescriptor.ProtocolVersions));
                        Console.WriteLine("\t+ Descriptor publication time: {0}", this.RendezvousDescriptor.PublicationTime);
                        Console.WriteLine("\t+ Introduction point count: {0}", this.RendezvousDescriptor.AdvertisedIntroPoints.Length);
                        Console.WriteLine("\t+ Permanent key loaded successfully?: {0}", this.RendezvousDescriptor.PermanentPublicKey != null);
                        Console.WriteLine("\t+ Service public key loaded successfully?: {0}\n", this.RendezvousDescriptor.ServicePublicKey != null);
                        return true;
                    }
                }
            }
            else
            {
                Console.WriteLine("[!] Unable to complete descriptor fetch, invalid response received.");
                this.DescriptorFetchCompleted = true;
            }
            return false;
        }

        public bool ConnectTo(String OnionAddress, int Timeout=15)
        {
            this.ResetValue = Timeout;
            this.OnionAddress = OnionAddress;
            bool ConnectionSuccessful = false;
            Console.Write("[+] Subscribing to HS_DESC events... ");
            if (TORComm.Active.CommandInterface.SubscribeToEvents(RequiredEventSubscriptions))
            {
                Console.WriteLine("Done.\n[+] Attempting to retrieve rendezvous descriptor.");
                if(this.RetrieveAndLoadRendezvousDescriptor())
                {
                    Console.WriteLine("[+] Rendezvous descriptor loaded successfully!");
                }                
            }
            return ConnectionSuccessful;
        }

        public HiddenServiceHandler()
        {
            this.DescriptorFetchCompleted = false;
            this.TimeoutThread = new Thread(new ThreadStart(this.UnsubscribeOnTimeout));    
        }
    }
}