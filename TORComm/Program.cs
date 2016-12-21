using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TORComm
{
    class Program
    {
        static void Main(string[] args)
        {
            TORComm.Interface.CommandLine.CLInterface app = new Interface.CommandLine.CLInterface();
            app.StartApplication();
        }
    }
}
