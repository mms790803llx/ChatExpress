using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Numerics;
using static ChatExpress.CryptoUtils;
using System.Security.Cryptography;
using System.Linq;
using System.Windows;

namespace ChatExpress
{
    class UserUtils
    {
        public const string UserInfoPath = "UserData.dat";
        private static string username;
        public static string Username { get { return username; } set { username = value; } }
        private static string password;
        public static string Password { get { return password; } private set { password = value; } }
        public static Key AESKey { get { byte[] key = new byte[16];
                var nameArr = new UnicodeEncoding().GetBytes(Username);
                var pwdArr = new UnicodeEncoding().GetBytes(Password);
                var temp = new byte[pwdArr.Length + nameArr.Length];
                nameArr.CopyTo(temp, 0);
                pwdArr.CopyTo(temp, nameArr.Length - 1);
                var sha = SHA256.Create();
                var hash = sha.ComputeHash(temp);
                hash.CopyTo(key, 8);
                return new Key { PrivateKey = key, PublicKey = key };
            } }
        public static class ContactManager
        {
            
            public const string SelfInfoPath = "SelfInfo.dat";
            public const string ContactInfoPath = "ConctactsInfo.dat";
            private static Dictionary<byte[],Contact> contacts;
            private static bool initialized = false;
            public static void Initialize()
            {
                if (!File.Exists(ContactInfoPath))
                {
                    contacts = new Dictionary<byte[], Contact>();
                    var fileStream = File.Create(ContactInfoPath);
                    var cryptor = new ChatExpress.CryptoUtils.CryptoStream(fileStream,CryptoType.AES128,CryptWay.Encrypt,AESKey);
                    Serializer.XMLSerial<Dictionary<byte[], Contact>>(new Dictionary<byte[], Contact>[] { contacts}, cryptor);
                    fileStream.Close();
                    return;
                }
                
            }
            public static byte[] MakeID()
            {
                Initialize();
                MemoryStream cache = new MemoryStream();
                //8 bytes
                byte[] TimeNow = new BigInteger(new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds()).ToByteArray();
                cache.Write(TimeNow);
                //40 bytes  
                byte[] RandNum = new byte[40];
                new Random().NextBytes(RandNum);
                cache.Write(RandNum);
                //16 bytes
                byte[] UUID = Guid.NewGuid().ToByteArray();
                cache.Write(UUID);
                return cache.ToArray();
            }
            public static byte[] GetSelfID()
            {
                Initialize();
                if (!File.Exists(SelfInfoPath))
                {
                    MemoryStream cache = new MemoryStream();
                    byte[] TimeNow = new BigInteger(new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds()).ToByteArray();
                    cache.Write(TimeNow);
                    byte[] RandNum = new byte[40];
                    new Random().NextBytes(RandNum);
                    cache.Write(RandNum);
                    byte[] UUID = Guid.NewGuid().ToByteArray();
                    cache.Write(UUID);
                    var s = File.OpenWrite(SelfInfoPath);
                    s.Seek(0, SeekOrigin.Begin);
                    var result = cache.ToArray();
                    s.Write(result);
                    return result;
                }
                var stream = File.OpenRead(SelfInfoPath);
                stream.Seek(0, SeekOrigin.Begin);
                var id = new byte[64];
                stream.Read(id);
                stream.Close();
                return id;
            }
        }
        [Serializable]
        public class Contact
        {
            public string Name;
            public byte[] IPAddress;
            public byte[] ID;
            public Key ChatKeySM2;
            public Key ChatKeyAES;
        }
        private static bool checkUser(string username,string password,string userInfoPath)
        {
            var usrFile = File.OpenRead(userInfoPath);
            try
            {

                MessageBox.Show("Password:" + password + "\nUserName:" + username);
                var srcArray = new byte[usrFile.Length];
                usrFile.Seek(0, SeekOrigin.Begin);
                usrFile.Read(srcArray);
                MessageBox.Show("Origin:" + new BigInteger(srcArray).ToString());
                var pwdArray = SHA256.Create().ComputeHash(new UnicodeEncoding().GetBytes(password));

                var nameArray = SHA256.Create().ComputeHash(new UnicodeEncoding().GetBytes(username));
                

                //Encrypt the username with password.

                var together = nameArray.Concat(pwdArray).ToArray();
                var result = SHA256.Create().ComputeHash(together);

                usrFile.Close();
                MessageBox.Show("Verify:" + new BigInteger(result).ToString());

                if(result == srcArray)
                {
                    Password = password;
                    Username = username;
                    return true;

                }
                //MessageBox.Show(new BigInteger(nameArray).ToString());
                return false;
            }
            catch (Exception ex)
            {
                throw ex;
                try
                {
                    usrFile.Close();
                }
                catch (Exception exc)
                {
                    return false;
                }
                Console.WriteLine("=====User Check Failed,info:==================");
                Console.WriteLine(ex.ToString());
                Console.WriteLine("======================================");
                //MessageBox.Show(ex.ToString());
                return false;
            }
        }
        public static bool SetUpFirst(string username, string password)
        {
            return setUpFirst(username, password, UserInfoPath);
        }
        public static bool CheckUser(string username, string password)
        {
            return checkUser(username, password, UserInfoPath);
        }
        private static bool setUpFirst(string username,string password, string userInfoPath)
        {
            if (File.Exists(userInfoPath))
            {
                File.Delete(userInfoPath);
            }
            var usrFile = File.Create(userInfoPath);
            try
            {
                MessageBox.Show("Password:"+password+"\nUserName:"+username);
               var nameArray = SHA256.Create().ComputeHash(new UnicodeEncoding().GetBytes(username));
                var pwdArray = SHA256.Create().ComputeHash(new UnicodeEncoding().GetBytes(password));

                //Encrypt the username with password.

                var together = nameArray.Concat(pwdArray).ToArray();
                var result = SHA256.Create().ComputeHash(together);
                

                usrFile.Seek(0, SeekOrigin.Begin);
                usrFile.Write(result);
                usrFile.Flush();
                usrFile.Close();
                MessageBox.Show(new BigInteger(nameArray).ToString());
                nameArray = SHA256.Create().ComputeHash(new UnicodeEncoding().GetBytes(username));
                pwdArray = SHA256.Create().ComputeHash(new UnicodeEncoding().GetBytes(password));

                //Encrypt the username with password.

                together = nameArray.Concat(pwdArray).ToArray();
                result = SHA256.Create().ComputeHash(together);


                
                MessageBox.Show(new BigInteger(nameArray).ToString());
                return true;
            }catch(Exception ex)
            {
                //throw ex;
                try
                {
                    usrFile.Close();
                }catch(Exception exc)
                {
                    return false;
                }
                Console.WriteLine("=====User Set Up Failed,info:==================");
                Console.WriteLine(ex.ToString());
                Console.WriteLine("======================================");
                //MessageBox.Show(ex.ToString());
                return false;
            }
        }
    }
}
