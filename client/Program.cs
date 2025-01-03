using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Configuration;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using static System.Net.Mime.MediaTypeNames;

namespace client
{

    public static class SomeEncryption
    {
        static int keyLen = 1024 * 2;
        public static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keyLen);



        public static byte[] encrypt1(byte[] arr, string key)
        {
            rsa.FromXmlString(key);
            if (arr.Length >= keyLen / 8)
            {

                int neededListLen = arr.Length / 200;
                int addition = arr.Length % 200;


                int eachPartLen = 200;

                byte[] part = new byte[eachPartLen];
                int index = 0;

                List<byte[]> helper = new List<byte[]>();

                // create each part
                for (int i = 0; i < neededListLen; i++)
                {
                    for (int j = 0; j < eachPartLen; j++)
                    {
                        part[j] = arr[index];
                        index++;
                    }
                    helper.Add(rsa.Encrypt(part, true));

                }

                // add the last smaller part

                byte[] partAdd = new byte[addition];
                for (int i = 0; i < addition; i++)
                {
                    partAdd[i] = arr[index];
                    index++;
                }

                helper.Add(rsa.Encrypt(partAdd, true));



                int fullLen = helper.Count * (keyLen / 8);


                byte[] result = new byte[fullLen];
                index = 0;
                for (int i = 0; i < helper.Count; i++)
                {
                    byte[] C = helper[i];
                    for (int j = 0; j < C.Length; j++)
                    {
                        result[index] = C[j];
                        index++;
                    }
                }

                return result;

            }
            else
            {

                return rsa.Encrypt(arr, true);
            }
        }

        public static byte[] decrypt1(byte[] arr, string key)
        {
            int fullLen = 0;
            rsa.FromXmlString(key);
            if (arr.Length > (keyLen / 8))
            {
                int partsNum = arr.Length / (keyLen / 8);
                
                List<byte[]> helper = new List<byte[]>();
                byte[] part = new byte[keyLen / 8];
                int index = 0;

                for (int i = 0; i < partsNum; i++)
                {
                    for (int j = 0; j < part.Length; j++)
                    {
                        part[j] = arr[index];
                        index++;
                    }

                    helper.Add(rsa.Decrypt(part, true));// this part is ok
                    fullLen += helper[i].Length;
                }






                byte[] result = new byte[fullLen];
                index = 0;
                for (int i = 0; i < helper.Count; i++)
                {
                    byte[] c = helper[i];
                    for (int j = 0; j < c.Length; j++)
                    {
                        result[index] = c[j];
                        index++;
                    }
                }

                return result;

            }
            else
            {
                return rsa.Decrypt(arr, true);
            }


        }
    }


    public class AesEncryption
    {
        public static int keyLen = 32;
        public static int ivLen = 16;
        public static byte[] Encrypt(byte[] plainBytes, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                byte[] encryptedBytes;
                using (var msEncrypt = new System.IO.MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
                return encryptedBytes;
            }
        }
        public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                byte[] decryptedBytes;
                using (var msDecrypt = new System.IO.MemoryStream(ciphertext))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var msPlain = new System.IO.MemoryStream())
                        {
                            csDecrypt.CopyTo(msPlain);
                            decryptedBytes = msPlain.ToArray();
                        }
                    }
                }
                return decryptedBytes;
            }
        }
    }

    static class ToFromByteArray
    {
        public static T FromByteArray<T>(byte[] rawValue)
        {
            GCHandle handle = GCHandle.Alloc(rawValue, GCHandleType.Pinned);
            T structure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return structure;
        }

        public static byte[] ToByteArray(object value, int maxLength)
        {
            int rawsize = Marshal.SizeOf(value);
            byte[] rawdata = new byte[rawsize];
            GCHandle handle =
                GCHandle.Alloc(rawdata,
                GCHandleType.Pinned);
            Marshal.StructureToPtr(value,
                handle.AddrOfPinnedObject(),
                false);
            handle.Free();
            if (maxLength < rawdata.Length)
            {
                byte[] temp = new byte[maxLength];
                Array.Copy(rawdata, temp, maxLength);
                return temp;
            }
            else
            {
                return rawdata;
            }
        }
    }

    class ClientConnection
    {
        
        public static int DirectoryServerPort = 50002;
        public static int Routingport = 50001;
        public static int Listeningport = 50000;
        public int id;
        static int count = 0;
        public TcpClient Client { get; set; }

        public string[] publickeys;
        public byte[,] sharedSecrets;
        public byte[,] sharedIvs;

        public IPAddress[] route;
        private Stream stream;
        public ClientConnection(TcpClient client, IPAddress[] route1, string[] publickeys)
        {
            this.Client = client;

            this.route = new IPAddress[route1.Length];
            for (int i = 0; i < route.Length; i++) { this.route[i] = route1[i]; }

            this.stream = client.GetStream();
            this.id = count;
            count++;

            this.sharedSecrets = new byte[route.Length, AesEncryption.keyLen];
            this.sharedIvs = new byte[route.Length, AesEncryption.ivLen];
            this.publickeys = publickeys;
        }

        public void CreateAndsendInitiationMessage()
        {
            byte[] msg = new byte[(route.Length-1)*4 + route.Length*(AesEncryption.keyLen+ AesEncryption.ivLen)];
            int countPublicKeys = 0;
            int index = 0;
            int KeyIndex = 0;
            int IVIndex = 0;
            int IPIndex = 0;
            int secretArrayIndex = 0;
            int ivArrayIndex = 0;
            // Generate a random key and IV
            byte[] key = new byte[AesEncryption.keyLen]; // 256-bit key
            byte[] iv = new byte[AesEncryption.ivLen]; // 128-bit IV
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }
            //saving first pair
            for (int i = 0; i< AesEncryption.keyLen; i++)
            {
                this.sharedSecrets[secretArrayIndex,i] = key[i];
            }
            secretArrayIndex++;
            for (int i = 0; i < AesEncryption.ivLen; i++)
            {
                this.sharedIvs[ivArrayIndex, i] = iv[i];
            }
            ivArrayIndex++;

            // goes secret, iv, ip.....secret, iv.

            //adding first pair
            while (KeyIndex != AesEncryption.keyLen || IVIndex!= AesEncryption.ivLen)
            {
                if(KeyIndex != AesEncryption.keyLen)
                {
                    msg[index] = key[KeyIndex];
                    
                    KeyIndex++;
                }
                else
                {
                    msg[index] = iv[IVIndex];
                    
                    IVIndex++;
                }
                index++;
            }
            //adding the rest of the message and saving the secrets
            byte[] ip = new byte[4];

            for (int i = 0; i < route.Length-1; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ip[j] = route[i + 1].GetAddressBytes()[j];
                }
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(key);
                    rng.GetBytes(iv);
                }
                IVIndex = 0;
                KeyIndex = 0;
                IPIndex = 0;

                for (int j = 0; j < AesEncryption.keyLen; j++)
                {
                    this.sharedSecrets[secretArrayIndex, j] = key[j];
                }
                secretArrayIndex++;
                for (int j = 0; j < AesEncryption.ivLen; j++)
                {
                    this.sharedIvs[ivArrayIndex, j] = iv[j];
                }
                ivArrayIndex++;

                while (KeyIndex != AesEncryption.keyLen || IVIndex != AesEncryption.ivLen || IPIndex!=4)
                {
                    if(IPIndex!=4)
                    {
                        msg[index] = ip[IPIndex];
                        
                        index++;
                        IPIndex++;
                        
                    }
                    else if (KeyIndex != AesEncryption.keyLen)
                    {
                        msg[index] = key[KeyIndex];
                        index++;
                        KeyIndex++;
                    }
                    else
                    {
                        msg[index] = iv[IVIndex];
                        index++;
                        IVIndex++;
                    }
                }
            }

            

            // split to parts in the list
            byte[] save = new byte[ip.Length + AesEncryption.ivLen + AesEncryption.keyLen];
            int countSave = 0;
            List<byte[]> help = new List<byte[]> { };
            for (int i = 0; i < msg.Length; i++)
            {
                if(countSave >= save.Length)
                {
                    help.Add(save);
                    countSave = 0;
                    save = new byte[ip.Length + AesEncryption.ivLen + AesEncryption.keyLen];
                }
                save[countSave] = msg[i];
                countSave++;
            }

            //add the last short part
            byte[] save2 = new byte[AesEncryption.ivLen + AesEncryption.keyLen];
            for (int i = 0; i< save2.Length; i++)
            {
                save2[i] = msg[msg.Length - save2.Length + i];
            }
            help.Add(save2);



            int o = 0;

            int ListLen = 0;

            //encrypts the amount of times needed for every part

            int len = help.Count;
            byte[] second = null;
            for (int i = 0; i < len-1; i++)
            {
                second = help[help.Count - 1];
                help.RemoveAt(help.Count - 1);
                Console.WriteLine("the lenght of the thing i am encrypting"+connectArrays(help[help.Count - 1], second).Length);
                help[help.Count - 1] = SomeEncryption.encrypt1(connectArrays(help[help.Count - 1], second), publickeys[publickeys.Length-countPublicKeys-1]);
                countPublicKeys++;
            }

            ListLen = help[0].Length;
            Console.WriteLine("need to be 1:" + help.Count);
            
            //copy back to array
            byte[] msg1 = new byte[ListLen];
            index = 0;
            for (int i = 0; i < help.Count; i++)
            {
                byte[] C = help[i];
                for (int j = 0; j < C.Length; j++)
                {
                    msg1[index] = C[j];
                    index++;
                }
            }

            //Console.WriteLine("msg:");
            //for (int i = 0; i < msg.Length; i++)
            //{
            //    Console.Write(msg[i]);
            //}
            //Console.WriteLine(" ");

            //Console.WriteLine("msg1:");
            //for (int i = 0; i < msg.Length; i++)
            //{
            //    Console.Write(msg1[i]);
            //}

            //Console.WriteLine(" ");

            Console.WriteLine("the len of the msg is:" + msg1.Length);

            byte[] lenHeader = BitConverter.GetBytes(msg1.Length);
            this.stream.Write(lenHeader, 0, lenHeader.Length);
            this.stream.Write(msg1, 0, msg1.Length);
        }
        
        public byte[] connectArrays(byte[] first, byte[] second)
        {
            byte[] result = new byte[first.Length + second.Length];
            for (int i = 0; i < result.Length; i++)
            {
                if (i < first.Length)
                    result[i] = first[i];
                else
                    result[i] = second[i - first.Length];
            }
            return result;
        }


        public void SendMessage(string text)
        {
            byte[] msg = Encoding.UTF8.GetBytes(text);
            byte[] secret = new byte[AesEncryption.keyLen];
            byte[] iv = new byte[AesEncryption.ivLen];

            for (int i = 0; i < route.Length; i++)
            {
                for (int j = 0; j < AesEncryption.keyLen;j++)
                {
                    secret[j] = this.sharedSecrets[this.route.Length - i - 1, j];
                    
                }
                
                for (int j = 0; j < AesEncryption.ivLen; j++)
                {
                    iv[j] = this.sharedIvs[this.route.Length - i - 1, j];
                    
                }
                
                msg = AesEncryption.Encrypt(msg, secret, iv);
            }

            byte[] lenHeader = BitConverter.GetBytes(msg.Length);
            this.stream.Write(lenHeader, 0, lenHeader.Length);

            this.stream.Write(msg, 0, msg.Length);
        }
        
        public string Descrypt(byte[] bytes)
        {
            
            byte[] secret = new byte[AesEncryption.keyLen];
            byte[] iv = new byte[AesEncryption.ivLen];

            for (int i = 0; i < route.Length; i++)
            {
                for (int j = 0; j < AesEncryption.keyLen; j++)
                {
                    secret[j] = this.sharedSecrets[route.Length - i - 1, j];
                }
                for (int j = 0; j < AesEncryption.ivLen; j++)
                {
                    iv[j] = this.sharedIvs[route.Length - i - 1, j];
                }
                bytes = AesEncryption.Decrypt(bytes, secret, iv);
            }
            return Encoding.UTF8.GetString(bytes);
        }

    }

    static class Protocol
    {
        public static string PhraseSharedSecretMsg(string secret) { return ""; }
        public static string PhraseRegularMsg(string msg) { return ""; }
        public static string UnderstandMsg(string msg) { return ""; }
        public static string PhraseRequestFromDirectory() { return ""; }
        public static string UnderstandAnswerFromDirectory(string answer) { return ""; }
    }
    internal class Program
    {
        //As server
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
            TcpClient ClientLW = (TcpClient)obj1;
            

            var stream = ClientLW.GetStream();

            Thread myNewThread = new Thread(() => Thread_ServerListener3(ClientLW));
            myNewThread.Start();

            try
            {
                
                while (true)//server only reads for now
                {

                    //Console.WriteLine("server: what do you want to send as server?");
                    //string str = Console.ReadLine();
                    //Byte[] reply = Encoding.ASCII.GetBytes(str);
                    //stream.Write(reply, 0, reply.Length);
                    //Console.WriteLine("server: {1}: Sent: {0}", str, Thread.CurrentThread.ManagedThreadId);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                ClientLW.Close();
            }

        }

        public static void Thread_ServerListener3(Object obj)
        {
            TcpClient ClientL = (TcpClient)obj;
            var stream1 = ClientL.GetStream();
            string imei = String.Empty;

            byte[] key = new byte[AesEncryption.keyLen];
            byte[] iv = new byte[AesEncryption.ivLen];
            string data = null;
            byte[] lenHeader = new byte[4];

            stream1.Read(lenHeader, 0, lenHeader.Length);

            Byte[] bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];
            
            int i;
            try
            {
                while ((i = stream1.Read(bytes, 0, bytes.Length)) != 0)
                {
                    for (int j = 0; j < bytes.Length; j++)
                    {
                        if(j< AesEncryption.keyLen)
                        {
                            key[j] = bytes[j];
                        }
                        else
                        {
                            iv[j - AesEncryption.keyLen] = bytes[j];
                        }
                    }
                        
                    Console.WriteLine("Server: {1}: Received: {0}", data, Thread.CurrentThread.ManagedThreadId);

                    break;
                }

                
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                ClientL.Close();
            }

            

            stream1.Read(lenHeader, 0, lenHeader.Length);

            Byte[] bytes2 = new Byte[BitConverter.ToInt32(lenHeader, 0)];

            while (true)
            {
                while ((i = stream1.Read(bytes2, 0, bytes2.Length)) != 0)
                {
                    bytes2 = AesEncryption.Decrypt(bytes2, key, iv);
                    data = Encoding.UTF8.GetString(bytes2);
                    Console.WriteLine("Server: {1}: Received: {0}", data, Thread.CurrentThread.ManagedThreadId);

                    stream1.Read(lenHeader, 0, lenHeader.Length);

                    bytes2 = new Byte[BitConverter.ToInt32(lenHeader, 0)];

                    //server only reads for now

                    //string str = "got the info";
                    //Byte[] reply = Encoding.ASCII.GetBytes(str);
                    //stream1.Write(reply, 0, reply.Length);
                    //Console.WriteLine("server: {1}: Sent: {0}", str, Thread.CurrentThread.ManagedThreadId);

                }
            }
        }

        //As client
        public static void Thread_MainClient1()
        {
            string destination = GetLocalIPAddress(); //dooing loopback
            Thread myNewThread = new Thread(() => Thread_CreateAndWriteConnection2(destination, ClientConnection.Routingport));
            myNewThread.Start();
        }

        public static void Thread_CreateAndWriteConnection2(string destination, int connectionPort)
        {
            List<string> keysList = new List<string>{ };
            byte[] routeAndkeys = GetRouteAndKeys(destination, keysList);

            string[] keys = new string[keysList.Count];
            for (int i = 0; i < keysList.Count; i++)
            {
                keys[i] = keysList[i];
            }


            IPAddress[] route = new IPAddress[routeAndkeys.Length/4];
            byte[] ip = new byte[4];
            
            for (int i = 0; i < routeAndkeys.Length; i+=4)
            {
                for (int j = 0; j < ip.Length; j++)
                {
                    ip[j] = routeAndkeys[j + i];
                }
                route[i/4] = new IPAddress(ip);
            }


            try
            {
                var ipEndPoint = new IPEndPoint(route[0], connectionPort);

                TcpClient ClientLW = new TcpClient();
                ClientLW.Connect(ipEndPoint);
                
                ClientConnection connection = new ClientConnection(ClientLW, route, keys);

                connection.CreateAndsendInitiationMessage();



                Thread myNewThread = new Thread(() => Thread_ConnectionListner3(connection));
                myNewThread.Start();


                

                while (true)
                {
                    Console.WriteLine("client: enter text you would like to send");

                    string str = Console.ReadLine();

                    connection.SendMessage(str);
                }
                     
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e);
            }

        }

        public static void Thread_ConnectionListner3(ClientConnection connection)
        {
            Console.WriteLine("client listens");

            
            var stream = connection.Client.GetStream();
            string imei = String.Empty;

            string data = null;

            byte[] lenHeader = new byte[4];

            stream.Read(lenHeader, 0, lenHeader.Length);


            Byte[] bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];
            int i;
            try
            {
                while (true)
                {
                    while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                    {
                        data = connection.Descrypt(bytes);
                        

                        Console.WriteLine("Client: {1}: Received: {0}", data, Thread.CurrentThread.ManagedThreadId);

                        stream.Read(lenHeader, 0, lenHeader.Length);


                        bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];

                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                connection.Client.Close();
            }
        }
        public static string[] Generate_SharedSecret(int amount)
        {
            return new string[amount];
        }

        public static byte[] GetRouteAndKeys(string destination, List<string> keys)//in the future keys will be added to the ip bytes
        {
            var ipEndPoint = new IPEndPoint(IPAddress.Parse(GetLocalIPAddress()), ClientConnection.DirectoryServerPort);
            TcpClient Client = new TcpClient();
            Client.Connect(ipEndPoint);

            Stream stream = Client.GetStream();

            byte[] msg1 = IPAddress.Parse(destination).GetAddressBytes();
            byte[] msg = new byte[msg1.Length + 1];
            for (int j = 0; j < msg1.Length; j++)
            {
                msg[j] = msg1[j];
            }

            msg[msg1.Length] = 1;

            byte[] Header = BitConverter.GetBytes(msg.Length);
            stream.Write(Header, 0, Header.Length);
            stream.Write(msg, 0, msg.Length);


            byte[] lenHeader = new byte[4];

            stream.Read(lenHeader, 0, lenHeader.Length);

            Byte[] bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];

            int i;

            byte[] route = null;
            
            try
            {
                while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    route =  bytes;
                    break;
                }

                stream.Read(lenHeader, 0, lenHeader.Length);

                bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];

                while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    string[] k = Encoding.UTF8.GetString(bytes).Split(new string[] { "******" }, StringSplitOptions.None);
                    for (int j = 0; j<k.Length; j++)
                        keys.Add(k[j]); 
                    Console.WriteLine(keys[0]);
                    return route;
                    
                }


            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                Client.Close();
            }
            Console.WriteLine("error");
            return new byte[] { 0 };//error

            //IPAddress D = IPAddress.Parse(destination);
            //byte[] Dbytes = D.GetAddressBytes();
            //byte[] route = new byte[2 * Dbytes.Length];
            //for (int i = 0; i < route.Length; i++)
            //{
            //    if (i < Dbytes.Length)
            //        route[i] = Dbytes[i];
            //    else
            //        route[i] = Dbytes[i - Dbytes.Length];
            //}
            //return route;
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
            string MyIp = GetLocalIPAddress();


        





            Thread myNewThreadL = new Thread(() => Thread_MainListener1(MyIp, ClientConnection.Listeningport));
            myNewThreadL.Start();

            Thread myNewThreadC = new Thread(() => Thread_MainClient1());
            myNewThreadC.Start();
            
            
        }
    }
}
