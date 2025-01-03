using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Configuration;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace router
{
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

                //for (int i = 0; i < helper.Count; i++)
                //{
                //    Console.Write(helper[i].Length +">>>");

                //    rsa.FromXmlString(key);
                //    helper[i] = rsa.Encrypt(helper[i], true);

                //    fullLen += helper[i].Length;
                //    Console.Write(helper[i].Length);
                //}

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
                Console.WriteLine("the amount of parts:" + partsNum);
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





                //Console.Write("the len of each part after decryption:");
                //for (int i = 0; i< helper.Count; i++)
                //{
                //    Console.Write(helper[i].Length+ ">>>" );
                //    rsa.FromXmlString(key);

                //    byte[] save = helper[i];

                //    helper[i] = rsa.Decrypt(save, true);

                //    Console.WriteLine(helper[i].Length +", ");

                //    fullLen += helper[i].Length;
                //}

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


    class Connection
    {
        
        public static string MyPrivateKey;
        public static int DirectoryServerPort = 50002;
        public static int RouringPort = 50001;
        public static int EndPort = 50000;
        public TcpClient From;

        public TcpClient To;

        public byte[] SharedSecret = new byte[AesEncryption.keyLen];

        public byte[] SharedIV = new byte[AesEncryption.ivLen];


        public Stream streamBack;
        public Stream streamForward;

        public Connection(TcpClient f, TcpClient t, byte[] secret, byte[] iv)
        {
            this.From = f;
            this.To = t;
            this.streamBack = this.From.GetStream();
            this.streamForward = this.To.GetStream();
            
            for (int i = 0; i < SharedSecret.Length; i++) 
            {
                this.SharedSecret[i] = secret[i];    
            }
            for (int i = 0; i < SharedIV.Length; i++)
            {
                this.SharedIV[i] = iv[i];
            }
        
        }

        public void SendForth(byte[] msg)
        {
            msg = AesEncryption.Decrypt(msg, this.SharedSecret, this.SharedIV);
            byte[] lenHeader = BitConverter.GetBytes(msg.Length);
            this.streamForward.Write(lenHeader, 0, lenHeader.Length);

            this.streamForward.Write(msg, 0, msg.Length);
        }
        public void SendBack(byte[] msg)
        {
            msg = AesEncryption.Encrypt(msg, this.SharedSecret, this.SharedIV);

            byte[] lenHeader = BitConverter.GetBytes(msg.Length);
            this.streamBack.Write(lenHeader, 0, lenHeader.Length);

            this.streamBack.Write(msg, 0, msg.Length);
        }
    }

    static class Protocol
    {
        public static string UnderstandMsg(string Msg) { return ""; }
        public static string PhraseAdditionMsgToDirectory(string id) { return ""; }

    }

    internal class Program
    {
        public static void Thread_Main1(string ip, int port)
        {
            IPAddress localAddr = IPAddress.Parse(ip);
            TcpListener server = new TcpListener(localAddr, port);
            server.Start();
            try
            {
                while (true)
                {
                    TcpClient connectionBack = server.AcceptTcpClient();
                    Console.WriteLine("someone connected");
                    Thread myNewThread = new Thread(() => Thread_ListenFrom2(connectionBack));
                    myNewThread.Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
                server.Stop();
            }
        }

        public static void Thread_ListenFrom2(Object obj1)
        {
            
            TcpClient connectionBack = (TcpClient)obj1;
            var stream = connectionBack.GetStream();

            string imei = String.Empty;


            byte[] secret = new byte[AesEncryption.keyLen];
            byte[] iv = new byte[AesEncryption.ivLen];
            byte[] ip = new byte[4];
            

            IPAddress next = null;


            
            
            int i;
            Connection Rconnection = null;

            int index = 0;

            byte[] lenHeader = new byte[4];

            stream.Read(lenHeader, 0, lenHeader.Length);
            

            Byte[] bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];

        
            while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
            {
               // RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024 * 4);
                
                //rsa.FromXmlString(Connection.MyPrivateKey);

                //Console.WriteLine(Connection.MyPrivateKey);

                //bytes = rsa.Decrypt(bytes, true);
                bytes = SomeEncryption.decrypt1(bytes, Connection.MyPrivateKey);

                Console.WriteLine(bytes.Length);

                int msgLen = bytes.Length - AesEncryption.keyLen - AesEncryption.ivLen - 4;

                byte[] msg = new byte[msgLen];

                for (int j = 0; j < secret.Length; j++)
                {
                    secret[j] = bytes[index];
                    index++;
                    
                }
                
                for (int j = 0; j < iv.Length; j++)
                {
                    iv[j] = bytes[index];
                    index++;
                   
                }
                
                for (int j = 0; j < 4; j++)
                {
                    ip[j] = bytes[index];
                    index++;
                }
                for (int j = 0; j < msg.Length; j++)
                {
                    msg[j] = bytes[index];
                    index++;
                }

                next = new IPAddress(ip);

                Console.WriteLine(next);
                Console.WriteLine(msg.Length);
                //creating the connection forward

                var ipEndPoint = new IPEndPoint(next, Connection.RouringPort);

                if (msg.Length < (AesEncryption.ivLen + AesEncryption.keyLen + 4))
                {
                    ipEndPoint = new IPEndPoint(next, Connection.EndPort);
                }
                

                TcpClient connectionForward = new TcpClient();
                connectionForward.Connect(ipEndPoint);



                Rconnection = new Connection(connectionBack, connectionForward, secret, iv);

                
                byte[] lenHeader2 = BitConverter.GetBytes(msg.Length);
                Rconnection.streamForward.Write(lenHeader2, 0, lenHeader2.Length);
                
                Rconnection.streamForward.Write(msg, 0, msg.Length);

                //Rconnection.SendBack("got the info");



                Console.WriteLine("StartingCon: {1}: Sent: {0}", msg, Thread.CurrentThread.ManagedThreadId);

                break;
            }
            

            Console.WriteLine("made the connection");

            Thread myNewThread = new Thread(() => Thread_ListenTo3(Rconnection));
            myNewThread.Start();

            stream.Read(lenHeader, 0, lenHeader.Length);
            Byte[] bytes2 = new Byte[BitConverter.ToInt32(lenHeader, 0)];

            try
            {
                while (true)
                {
                    while ((i = stream.Read(bytes2, 0, bytes2.Length)) != 0)
                    {
                        Rconnection.SendForth(bytes2);
                        stream.Read(lenHeader, 0, lenHeader.Length);
                        bytes2 = new Byte[BitConverter.ToInt32(lenHeader, 0)];
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                connectionBack.Close();
            }
        }

        

        public static void Thread_ListenTo3(Object obj1)
        {
            Connection Rconnection = (Connection)obj1;
            
            Stream stream = Rconnection.streamForward;

            string imei = String.Empty;


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
                        Rconnection.SendBack(bytes);
                        stream.Read(lenHeader, 0, lenHeader.Length);
                        bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                //does something
            }

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

        public static void TellDirectoryYouLive()
        {
            var ipEndPoint = new IPEndPoint(IPAddress.Parse(GetLocalIPAddress()), Connection.DirectoryServerPort);
            TcpClient Client = new TcpClient();
            Client.Connect(ipEndPoint);

            Stream stream = Client.GetStream();

            byte[] msg1 = IPAddress.Parse(GetLocalIPAddress()).GetAddressBytes(); // i am directory server later will find out
            byte[] msg = new byte[msg1.Length + 1];
            for (int j = 0; j < msg1.Length; j++)
            {
                msg[j] = msg1[j];
            }

            msg[msg1.Length] = 0;
            


            byte[] Header = BitConverter.GetBytes(msg.Length);
            stream.Write(Header, 0, Header.Length);
            stream.Write(msg, 0, msg.Length);


            byte[] lenHeader = new byte[4];

            stream.Read(lenHeader, 0, lenHeader.Length);

            Byte[] bytes = new Byte[BitConverter.ToInt32(lenHeader, 0)];

            int i;

            try
            {
                while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    Connection.MyPrivateKey = Encoding.UTF8.GetString(bytes);
                    break;
                }

                


            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.ToString());
                Client.Close();
            }

        }
        static void Main(string[] args)
        {
            string MyIp = GetLocalIPAddress();

            

            TellDirectoryYouLive();

            



            Thread_Main1(GetLocalIPAddress(), Connection.RouringPort);
        }
    }
}
