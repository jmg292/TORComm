using System;
using System.Collections.Concurrent;

namespace TORComm.TestBed.Distributed.Network
{
    public class Relay
    {
        public Components.Distributed.NetworkParameters NetworkParameters;

        private Components.Distributed.PeeringTableObject PeeringTable;
        private Components.Distributed.InitialPeeringParameters InitialParameters;
        
        private ConcurrentBag<Interfaces.InboundInterface> InboundPeerConnections;
        private ConcurrentBag<Interfaces.OutboundInterface> OutboundPeerConnections;

        private void ConfigureRelayObject(Components.Distributed.InitialPeeringParameters parameters)
        {
            this.InitialParameters = parameters;
        }

        public Relay(Components.Distributed.InitialPeeringParameters parameters)
        {
            this.ConfigureRelayObject(parameters);
        }

        public Relay(String address, int port)
        {
            Components.Distributed.InitialPeeringParameters parameters = new Components.Distributed.InitialPeeringParameters();
            parameters.IsFounder = false;
            parameters.address = address;
            parameters.port = port;
            this.ConfigureRelayObject(parameters);     
        }

        public Relay()
        {
            Components.Distributed.InitialPeeringParameters parameters = new Components.Distributed.InitialPeeringParameters();
            parameters.IsFounder = true;
            this.ConfigureRelayObject(parameters);
        }
    }
}