/*******************************************************************
 *                                                                 *
 *        Project: PS4-DNSfilter                                   *
 *        Author: SirMick                                          *
 *        Github : https://github.com/SirMick56/PS4-DNSfilter      *
 *                                                                 *
 * Description:                                                    *
 * A local DNS service to filter URLs for PS4 to prevent unwanted  *
 * updates.                                                        *
 *                                                                 *
 *******************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PS4_DNSfilter
{
    class Program
    {
        private static HashSet<string> whitelistDomains = new HashSet<string>();
        private static HashSet<string> blacklistDomains = new HashSet<string>();

        static void Main(string[] args)
        {
            LoadDomains();
            Console.WriteLine("Starting DNS Server...");
            try
            {
                StartDnsServer();
            }
            catch (SocketException ex) when (ex.ErrorCode == 10048)
            {
                Console.WriteLine("Port 53 is already in use. Please close any other applications using this port and try again.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        static void LoadDomains()
        {
            // Charger les domaines de la liste blanche
            if (File.Exists("whitelist.conf"))
            {
                var lines = File.ReadAllLines("whitelist.conf");
                foreach (var line in lines)
                {
                    whitelistDomains.Add(line.Trim().ToLower());
                }
                Console.WriteLine("Loaded whitelist domains from whitelist.conf.");
            }

            // Charger les domaines de la liste noire
            if (File.Exists("blacklist.conf"))
            {
                var lines = File.ReadAllLines("blacklist.conf");
                foreach (var line in lines)
                {
                    blacklistDomains.Add(line.Trim().ToLower());
                }
                Console.WriteLine("Loaded blacklist domains from blacklist.conf.");
            }
            else
            {
                var defaultBlockedDomains = new[] { "playstation.net", "playstation.com", "akamai.net", "akadns.net" };
                File.WriteAllLines("blacklist.conf", defaultBlockedDomains);
                blacklistDomains = new HashSet<string>(defaultBlockedDomains.Select(d => d.ToLower()));
                Console.WriteLine("Created default blacklist.conf with basic domains.");
            }
        }

        static void SaveBlockedDomain(string domain)
        {
            if (!blacklistDomains.Contains(domain))
            {
                blacklistDomains.Add(domain);
                File.AppendAllText("blacklist.conf", domain + Environment.NewLine);
                Console.WriteLine($"Saved blocked domain: {domain}");
            }
        }

        static void StartDnsServer()
        {
            using (UdpClient udpServer = new UdpClient(53))
            {
                IPEndPoint? remoteEP = null;

                while (true)
                {
                    byte[] data = udpServer.Receive(ref remoteEP);
                    if (remoteEP == null)
                    {
                        Console.WriteLine("Failed to receive data");
                        continue;
                    }

                    var query = ParseQuery(data);
                    if (query == null)
                    {
                        Console.WriteLine("Failed to parse DNS query");
                        continue;
                    }

                    Console.WriteLine($"Received request for {query.Question.Name} from {remoteEP.Address}");

                    if (ShouldBlock(query))
                    {
                        var response = CreateBlockedResponse(query);
                        udpServer.Send(response, response.Length, remoteEP);
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\u001b[1mBlocked {query.Question.Name}\u001b[0m");
                        Console.ResetColor();
                        SaveBlockedDomain(query.Question.Name);
                    }
                    else
                    {
                        var response = ForwardRequest(data);
                        udpServer.Send(response, response.Length, remoteEP);
                        Console.WriteLine($"Forwarded {query.Question.Name}");
                    }
                }
            }
        }

        static DnsMessage? ParseQuery(byte[] data)
        {
            try
            {
                var stream = new MemoryStream(data);
                var reader = new BinaryReader(stream);
                var header = new DnsHeader(reader);
                var question = new DnsQuestion(reader);
                return new DnsMessage { Header = header, Question = question };
            }
            catch
            {
                return null;
            }
        }

        static bool ShouldBlock(DnsMessage query)
        {
            string domain = query.Question.Name.ToLower();

            // Si le domaine est dans la liste blanche, ne pas bloquer
            if (whitelistDomains.Any(w => domain.Contains(w)))
            {
                return false;
            }

            // Si le domaine est dans la liste noire, bloquer
            if (blacklistDomains.Any(b => domain.Contains(b)))
            {
                return true;
            }

            // Si le domaine n'est ni dans la liste blanche ni dans la liste noire, ne pas bloquer par défaut
            return false;
        }

        static byte[] CreateBlockedResponse(DnsMessage query)
        {
            var response = new DnsMessage
            {
                Header = query.Header,
                Question = query.Question
            };
            response.Header.QR = true;
            response.Header.RCode = 3; // NXDOMAIN

            // Clear counts
            response.Header.QDCOUNT = 1;
            response.Header.ANCOUNT = 0;
            response.Header.NSCOUNT = 0;
            response.Header.ARCOUNT = 0;

            return response.ToArray();
        }

        static byte[] ForwardRequest(byte[] data)
        {
            var client = new UdpClient("8.8.8.8", 53);
            client.Send(data, data.Length);
            var remoteEP = new IPEndPoint(IPAddress.Any, 0);
            return client.Receive(ref remoteEP);
        }
    }

    public class DnsMessage
    {
        public DnsHeader Header { get; set; } = new DnsHeader();
        public DnsQuestion Question { get; set; } = new DnsQuestion();
        public List<DnsResourceRecord> Answers { get; set; } = new List<DnsResourceRecord>();

        public byte[] ToArray()
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                Header.Write(writer);
                Question.Write(writer);
                foreach (var answer in Answers)
                {
                    answer.Write(writer);
                }
                return stream.ToArray();
            }
        }
    }

    public class DnsHeader
    {
        public bool QR { get; set; }
        public int RCode { get; set; }
        public int QDCOUNT { get; set; }
        public int ANCOUNT { get; set; }
        public int NSCOUNT { get; set; }
        public int ARCOUNT { get; set; }

        public DnsHeader() { }

        public DnsHeader(BinaryReader reader)
        {
            reader.BaseStream.Seek(2, SeekOrigin.Current); // Skip ID
            ushort flags = reader.ReadUInt16();
            QR = (flags & 0x8000) != 0;
            RCode = flags & 0xF; // Extract RCode
            QDCOUNT = reader.ReadUInt16();
            ANCOUNT = reader.ReadUInt16();
            NSCOUNT = reader.ReadUInt16();
            ARCOUNT = reader.ReadUInt16();
        }

        public void Write(BinaryWriter writer)
        {
            ushort flags = (ushort)(QR ? 0x8000 : 0x0000);
            flags |= (ushort)(RCode & 0xF); // Add RCode to flags
            writer.Write(flags);
            writer.Write((ushort)QDCOUNT);
            writer.Write((ushort)ANCOUNT);
            writer.Write((ushort)NSCOUNT);
            writer.Write((ushort)ARCOUNT);
        }
    }

    public class DnsQuestion
    {
        public string Name { get; set; } = string.Empty;
        public ushort Type { get; set; }
        public ushort Class { get; set; }

        public DnsQuestion() { }

        public DnsQuestion(BinaryReader reader)
        {
            Name = ReadName(reader);
            Type = reader.ReadUInt16();
            Class = reader.ReadUInt16();
        }

        public void Write(BinaryWriter writer)
        {
            WriteName(writer, Name);
            writer.Write(Type);
            writer.Write(Class);
        }

        private string ReadName(BinaryReader reader)
        {
            StringBuilder name = new StringBuilder();
            while (true)
            {
                byte length = reader.ReadByte();
                if (length == 0) break;

                if (name.Length > 0)
                {
                    name.Append('.');
                }

                name.Append(Encoding.ASCII.GetString(reader.ReadBytes(length)));
            }
            return name.ToString();
        }

        private void WriteName(BinaryWriter writer, string name)
        {
            foreach (var label in name.Split('.'))
            {
                writer.Write((byte)label.Length);
                writer.Write(Encoding.ASCII.GetBytes(label));
            }
            writer.Write((byte)0);
        }
    }

    public class DnsResourceRecord
    {
        public string Name { get; set; } = string.Empty;
        public ushort Type { get; set; }
        public ushort Class { get; set; }
        public uint TTL { get; set; }
        public byte[] Data { get; set; } = Array.Empty<byte>();

        public void Write(BinaryWriter writer)
        {
            WriteName(writer, Name);
            writer.Write(Type);
            writer.Write(Class);
            writer.Write(TTL);
            writer.Write((ushort)Data.Length);
            writer.Write(Data);
        }

        private void WriteName(BinaryWriter writer, string name)
        {
            foreach (var label in name.Split('.'))
            {
                writer.Write((byte)label.Length);
                writer.Write(Encoding.ASCII.GetBytes(label));
            }
            writer.Write((byte)0);
        }
    }
}
