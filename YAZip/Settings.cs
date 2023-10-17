using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YAZip
{
    public sealed class Settings
    {
        private Settings() { }
        private static Settings instance = null;
        public static Settings Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new Settings();
                }
                return instance;
            }
        }

        public bool ds3comply = false;

        public string key =@"";
    }
}
