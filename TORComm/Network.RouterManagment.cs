using System;
using System.Linq;

namespace TORComm.Network
{
    public static class RouterManagement
    {
        public static TORComm.Components.Network.RouterObject GetRouterByName(String RouterName)
        {
            var QueryResult = from x in TORComm.Active.RouterStorage.FastRouters where x.Value.nickname == RouterName select x;
            if(!(QueryResult.Any()))
            {
                QueryResult = from x in TORComm.Active.RouterStorage.SlowRouters where x.Value.nickname == RouterName select x;
            }
            TORComm.Components.Network.RouterObject router = QueryResult.Count() > 0 ? QueryResult.FirstOrDefault().Value : null;
            return router;
        }
    }
}