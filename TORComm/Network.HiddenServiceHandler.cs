using System;
using System.Threading;

namespace TORComm.Network
{
    public class HiddenServiceHandler
    {
        private int ResetValue;
        private int TimeoutCounter;
        private String OnionAddress;
        private Thread TimeoutThread;
        private bool DescriptorFetchCompleted;
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
                        Console.WriteLine("[+] Descriptor contains requested content: {0}", ResponseObject.ProcessedResponse);
                        this.ResetTimeout();
                    }
                }
            }                 
        }

        private void ResolveOnionAddress()
        {
            this.TimeoutThread.Start();
            this.SubscribeToEventHandler();
            String CmdResponse = TORComm.Active.CommandInterface.SendCommand(String.Format("HSFETCH {0}", OnionAddress));
            if(TORComm.Active.CommandInterface.ResponseOK(CmdResponse))
            {
                Console.WriteLine("[+] HSFETCH command sent successfully, awaiting response.");
            }
            else
            {
                Console.WriteLine("[+] Invalid response: {0}", CmdResponse);
            }
        }

        public bool ConnectTo(String OnionAddress, int Timeout=15)
        {
            this.ResetValue = Timeout;
            this.OnionAddress = OnionAddress;
            bool ConnectionSuccessful = false;
            if (TORComm.Active.CommandInterface.SubscribeToEvents(RequiredEventSubscriptions))
            {
                this.ResolveOnionAddress();
                while (!(this.DescriptorFetchCompleted))
                {
                    Thread.Sleep(500);
                }
                Console.WriteLine(TORComm.Active.CommandInterface.SendCommand(String.Format("GETINFO hs/service/desc/id/{0}", this.OnionAddress)));
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