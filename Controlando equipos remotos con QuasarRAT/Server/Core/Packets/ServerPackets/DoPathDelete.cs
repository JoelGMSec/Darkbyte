﻿using System;
using xServer.Core.Networking;
using xServer.Enums;

namespace xServer.Core.Packets.ServerPackets
{
    [Serializable]
    public class DoPathDelete : IPacket
    {
        public string Path { get; set; }

        public PathType PathType { get; set; }

        public DoPathDelete()
        {
        }

        public DoPathDelete(string path, PathType pathtype)
        {
            this.Path = path;
            this.PathType = pathtype;
        }

        public void Execute(Client client)
        {
            client.Send(this);
        }
    }
}