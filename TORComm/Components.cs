using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace TORComm.Components
{
    public static class Security
    {
        public class KeySequenceObject
        {
            public String KeyToken;
            public int CurrentIndex;
            public int SequenceOffset;
            public bool IgnoreMaxIndex;
            public KeySequenceObject()
            {
                this.CurrentIndex = 0;
                this.SequenceOffset = 0;
                this.IgnoreMaxIndex = false;
                this.KeyToken = String.Empty;
            }
        }

        public static class HandshakeInformation
        {
            public static int BufferSize = 4096;

            public static Byte[] header = new Byte[] { 0x03, 0x9B, 0x03, 0xAE, 0x03, 0xBB, 0x03, 0xB1, 0x03, 0x8D, 0x03, 0xC4, 0x03, 0xBF, 0x03, 0xC2 };

            public enum HandshakeStage
            {
                ASSOC = 0x2401,
                SYN = 0x2416,
                ACK = 0x2406,
                NACK = 0x2415,
                DONE = 0x2499,
                EOT = 0x2404
            }
        }

        public class KeyConversionAssistant
        {
            public int index;
            public String[] SplitMessage;
            public RSACryptoServiceProvider ConvertedKey;

            public KeyConversionAssistant(int i, String[] s)
            {
                this.index = i;
                this.SplitMessage = s;
                this.ConvertedKey = null;
            }
        }
    }

    public static class Network
    {
        // We will not use a router that does not report the following flags
        public static String[] RequiredRouterFlags = new String[]
        {
            "Running",
            "Stable",
            "Valid"
        };

        public enum ConnectionMode
        {
            CLIENT = 0,
            SERVER = 1
        }

        public enum CircuitStatus
        {
            LAUNCHED = 0,
            BUILT = 1,
            EXTENDED = 2,
            FAILED = 3,
            CLOSED = 4
        }

        public enum CircuitPurpose
        {
            GENERAL = 0,
            HS_CLIENT_INTRO = 1,
            HS_CLIENT_REND = 2,
            HS_SERVICE_INTRO = 3,
            HS_SERVICE_REND = 4,
            TESTING = 5,
            CONTROLLER = 6,
            MEASURE_TIMEOUT = 7,
            UNLISTED_UNKNOWN = 8
        }

        public enum CircuitReason
        {
            NONE = 0,
            TORPROTOCOL = 1,
            INTERNAL = 2,
            REQUESTED = 3,
            HIBERNATING = 4,
            RESOURCELIMIT = 5,
            CONNECTFAILED = 6,
            OR_IDENTITY = 7,
            OR_CONN_CLOSED = 8,
            TIMEOUT = 9,
            FINISHED = 10,
            DESTROYED = 11,
            NOPATH = 12,
            NOSUCHSERVICE = 13,
            MEASUREMENT_EXPIRED = 14
        }

        public class SessionParameterObject
        {
            public int offset;
            public int ServerIVTrack;
            public int ClientIVTrack;
            public int ServerKeyTrack;
            public int ClientKeyTrack;
            public bool CompletedNoErrors;
            public ECDiffieHellmanCngPublicKey PubKey;
            public ECDiffieHellmanCng PrivateKeyObject;

            public SessionParameterObject()
            {
                this.offset = 0;
                this.ServerIVTrack = 0;
                this.ClientIVTrack = 0;
                this.ServerKeyTrack = 0;
                this.ClientKeyTrack = 0;
                this.CompletedNoErrors = false;

                this.PubKey = null;
                this.PrivateKeyObject = null;
            }
        }

        public class RouterObject
        {
            // Router identity and connection info
            public String digest;
            public String address;
            public String nickname;
            public String identity;
            public String CountryCode;

            public List<int> Ports;

            public int bandwidth;

            /*
             *  NOTE: There are plenty of other flags tracked
             *  by the TOR network.  The below flags are the 
             *  only ones we care about.  We use these flags
             *  to determine which routers to prioritize for
             *  which tasks inside of the TOR network
             */ 

            // Critical status flags
            public bool IsFast;
            public bool IsValid;
            public bool IsStable;
            public bool IsRunning;
            
            // Services offered by router
            public bool IsExit;
            public bool IsGuard;
            public bool IsHSDirectory;
            public bool IsDirectoryAuthority;

            public RouterObject()
            {
                this.bandwidth = 0;
                this.IsFast = false;
                this.IsExit = false;
                this.IsGuard = false;
                this.IsValid = false;
                this.IsStable = false;
                this.IsRunning = false;
                this.IsHSDirectory = false;
                this.digest = String.Empty;
                this.address = String.Empty;
                this.nickname = String.Empty;
                this.identity = String.Empty;
                this.Ports = new List<int>();
                this.CountryCode = String.Empty;
                this.IsDirectoryAuthority = false;
            }
        }

        public class RouterStorageObject
        {
            public ConcurrentBag<String> ExitNodeIndex;
            public ConcurrentBag<String> GuardNodeIndex;
            public ConcurrentBag<String> DirectoryAuthorityIndex;
            public ConcurrentBag<String> HiddenServiceDirectoryIndex;

            public ConcurrentDictionary<String, RouterObject> FastRouters;
            public ConcurrentDictionary<String, RouterObject> SlowRouters;

            public RouterStorageObject()
            {
                this.ExitNodeIndex = new ConcurrentBag<string>();
                this.GuardNodeIndex = new ConcurrentBag<string>();
                this.DirectoryAuthorityIndex = new ConcurrentBag<string>();
                this.HiddenServiceDirectoryIndex = new ConcurrentBag<string>();
                this.FastRouters = new ConcurrentDictionary<string, RouterObject>();
                this.SlowRouters = new ConcurrentDictionary<string, RouterObject>();
            }
        }

        public class CircuitObject
        {
            public String identity;
            public CircuitStatus Status;
            public CircuitReason Reason;
            public DateTime CreationTime;
            public CircuitPurpose Purpose;
            public RouterObject[] Routers;

            public CircuitObject()
            {
                this.Routers = null;
                this.identity = String.Empty;
                this.Reason = CircuitReason.NONE;
                this.Status = CircuitStatus.CLOSED;
                this.CreationTime = DateTime.MinValue;
                this.Purpose = CircuitPurpose.UNLISTED_UNKNOWN;
            }
        }

        public class IntroductionPointObject
        {
            public String identity;
            public RouterObject router;
            public RSACryptoServiceProvider PublicKey;

            public IntroductionPointObject()
            {
                this.router = null;
                this.PublicKey = null;
                this.identity = String.Empty;
            }
        }

        public class RendezvousDescriptorObject
        {
            public String identity;
            public String SecretIdentity;
            public int DescriptorVersion;
            public int[] ProtocolVersions;
            public DateTime PublicationTime;
            public RSACryptoServiceProvider ServicePublicKey;
            public RSACryptoServiceProvider PermanentPublicKey;
            public IntroductionPointObject[] AdvertisedIntroPoints;

            public RendezvousDescriptorObject()
            {
                this.DescriptorVersion = 0;
                this.identity = String.Empty;
                this.ProtocolVersions = null;
                this.ServicePublicKey = null;
                this.PermanentPublicKey = null;
                this.AdvertisedIntroPoints = null;
                this.SecretIdentity = String.Empty;
                this.PublicationTime = DateTime.MinValue;
            }
        }

        public class AsyncResponseObject
        {
            public Byte[] RxBuffer;
            public String CallbackIdentity;
            public String ProcessedResponse;

            public AsyncResponseObject(int BufferSize=40960)
            {
                this.RxBuffer = new Byte[BufferSize];
                this.ProcessedResponse = String.Empty;
                this.CallbackIdentity = Guid.NewGuid().ToString();
            }
        }
    }

    public static class TorProcess
    {
        public class DynamicProperties
        {
            public int SocksPort;
            public int ControlPort;
            public String ControlPassword;

            public DynamicProperties()
            {
                this.SocksPort = 0;
                this.ControlPort = 0;
                this.ControlPassword = String.Empty;
            }
        }
    }
}