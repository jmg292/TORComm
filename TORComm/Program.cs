using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;

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
