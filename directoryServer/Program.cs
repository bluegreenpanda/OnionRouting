using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Data;
using System.IO;

namespace directory_server
{

    static class DataBase
    {
        public static List<byte[]> ipAdress = new List<byte[]> { };
        public static List<string> publicKeys = new List<string> { }; 
      //  public static List<> keys;

        public static void AddTodata(byte[] ifClientAndip, string publicKey) 
        {
            ipAdress.Add(ifClientAndip);
            publicKeys.Add(publicKey);
        }
        

        public static void SendRouteAndKeys(byte[] ip, Stream stream)//telling him to do loopback for now
        {
            int stop = 0;
            using (var num = new SecureRandomNumberGenerator())
            {
                
                 stop = num.GenerateRandomNumberInRange(0, ipAdress.Count);               
            }
            if (stop == ipAdress.Count)
                stop -= 1;


            byte[] route = new byte[3 * ip.Length];// for now only one stop


            byte[] ip2 = ipAdress[stop];


            for (int i = 0; i < 4; i++)
            {
                route[i] = ip2[i];
            }

            
            for (int i = 0; i < route.Length-4; i++)
            {
                if (i < ip2.Length)
                    route[i+4] = ip[i];
                else
                    route[i+4] = ip[i - ip.Length];
            }

            Console.WriteLine(new IPAddress(ip));
            Console.WriteLine(new IPAddress(ip2));


            byte[] Header = BitConverter.GetBytes(route.Length);// the ips

            stream.Write(Header, 0, Header.Length);
            stream.Write(route, 0, route.Length);

            int ipIndex = -1;
            for (ipIndex = 0; ipIndex< ipAdress.Count; ipIndex++) 
            {
                if (Enumerable.SequenceEqual(ip, ipAdress[ipIndex]))
                {
                    break;
                }
            }

            Console.WriteLine("the ip is"+ new IPAddress(ip));
            Console.WriteLine("the ip that is in the system is:" +new IPAddress(ipAdress[0]));
            string StringKeys = publicKeys[stop] +"******"+ publicKeys[ipIndex];

            byte[] keys = Encoding.UTF8.GetBytes(StringKeys);

            Header = BitConverter.GetBytes(keys.Length);

            stream.Write(Header, 0, Header.Length);
            stream.Write(keys, 0, keys.Length);

        }
    }

    public class SecureRandomNumberGenerator : IDisposable
    {
        private RandomNumberGenerator rng = RandomNumberGenerator.Create();

        public int GenerateRandomNumberInRange(int minValue, int maxValue)
        {
            if (minValue >= maxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(minValue), "minValue must be less than maxValue");
            }

            int range = maxValue - minValue + 1;
            byte[] uint32Buffer = new byte[4];

            int result;
            do
            {
                rng.GetBytes(uint32Buffer);
                uint randomUint = BitConverter.ToUInt32(uint32Buffer, 0);
                result = (int)(randomUint % range);
            } while (result < 0 || result >= range);

            return minValue + result;
        }

        public void Dispose()
        {
            rng.Dispose();
        }
    }
    static class Protocol
    {
        public static string UnderstandMsg(string msg) { return ""; }
    }
    internal class Program
    {
        


        public static void Thread_MainListener1(string ip, int port)
        {
            IPAddress localAddr = IPAddress.Parse(ip);
            TcpListener server = new TcpListener(localAddr, port);
            server.Start();
            try
            {
                while (true)
                {
                    TcpClient clientLW = server.AcceptTcpClient();
                    Console.WriteLine("server: got client");
                    Thread myNewThread = new Thread(() => Thread_HandleAsServer2(clientLW));
                    myNewThread.Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
                server.Stop();
            }
        }

        public static void Thread_HandleAsServer2(Object obj1)
        {
            TcpClient Client = (TcpClient)obj1;
            var stream = Client.GetStream();

            string imei = String.Empty;

            
            string data = null;
            byte[] lenHeader = new byte[4];

            stream.Read(lenHeader, 0, lenHeader.Length);

            Byte[] bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];

            int i;

            try
            {
                while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    if (bytes[bytes.Length-1] == 1)//means asking for route
                    {
                        byte[] ipB = new byte[4];
                        for (int i2 = 0; i2 < ipB.Length; i2++)
                        {
                            ipB[i2] = bytes[i2];
                        }

                        DataBase.SendRouteAndKeys(ipB, stream);

                        //byte[] Header = BitConverter.GetBytes(route.Length);

                        //stream.Write(Header, 0, Header.Length);
                        //stream.Write(route, 0, route.Length);

                        
                    }
                    else
                    {
                        byte[] ip = new byte[4];
                        
                        for (int i2 = 0; i2 < ip.Length; i2++)
                        {
                            ip[i2] = bytes[i2];
                        }
                         
                        Console.WriteLine("got"+ ip);

                        using (var rsa = new RSACryptoServiceProvider(1024*2))
                        {
                            string publicKey = rsa.ToXmlString(false);
                            string privateKey = rsa.ToXmlString(true);
                            Console.WriteLine("generated keys");
                            DataBase.AddTodata(ip, publicKey);

                            byte[] msg = Encoding.UTF8.GetBytes(privateKey);
                            byte[] Header = BitConverter.GetBytes(msg.Length);

                            stream.Write(Header, 0, Header.Length);
                            stream.Write(msg, 0, msg.Length);
                        }


                            

                    }

                    break;
                }


            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                Client.Close();
            }

            Client.Close();
        }




        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
        static void Main(string[] args)
        {
            int port = 50002;

            string MyIp = GetLocalIPAddress();

            Thread_MainListener1(MyIp, port);

        }
    }
}
