using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using CryptLibrary;
using System.Windows;

namespace ChatExpress
{
    class CryptoUtils
    {
        public class Key
        {
            public byte[] PublicKey;
            public byte[] PrivateKey;
        }
        public enum CryptoType
        {
            RSA2048,AES128,SM2
        }
        public enum CryptWay
        {
            Encrypt,Decrypt
        }
        public class CryptoStream : Stream
        {
            public CryptoStream( Stream output,CryptoType crypto, CryptWay way, Key key)
            {
                Output = output;
                Crypto = crypto;
                Way = way;
                Password = key;
                cache = new MemoryStream();
            }
            public Stream Output;
            
            public CryptoStream(CryptoType crypto,CryptWay way,Key key)
            {
                Crypto = crypto;
                Way = way;
                Password = key;
                cache = new MemoryStream();
                Output = cache;
            }
            public Key Password;
            public CryptoType Crypto;
            public CryptWay Way;
            public override bool CanRead { get { return true; } }
            private MemoryStream cache = new MemoryStream();
            public override bool CanSeek { get { return true; } }
            public override bool CanWrite { get { return true; } }
            public override long Length { get { return cache.Length; } }
            public override long Position { get {return cache.Position; }set { cache.Position = value; } }
            private readonly object ioLock = 1  ;
            private long lastFlush = 0;
            /// <summary>
            /// Writes the content to the <see cref="ChatExpress.CryptoUtils.CryptoStream.Output"/>
            /// </summary>
            public override void Flush()
            {
                lock (ioLock)
                {
                    if (Output != null && cache.Position < cache.Length - 1&&cache.Length>0)
                    {
                        if (lastFlush > cache.Length - 1)
                        {
                            lastFlush = cache.Length-1;
                            return;
                        }
                        long posBefore = Position;
                        Position = lastFlush;
                        for(long i = lastFlush; i < cache.Length - cache.Position - 1; i++)
                        {
                            Output.WriteByte((byte)cache.ReadByte());
                        }
                        Position = posBefore;
                    }
                }
            }
            /// <summary>
            /// Clears the cache
            /// </summary>
            public void Clear()
            {
                cache.Close();
                cache.Dispose();
                cache = new MemoryStream();
                lastFlush = 0;
            }
            /// <summary>
            /// read the encrypted or decrypted content.
            /// </summary>
            /// <param name="buffer"></param>
            /// <param name="offset"></param>
            /// <param name="count"></param>
            /// <returns></returns>
            public override int Read(byte[] buffer, int offset, int count)
            {
                int a = cache.Read(buffer, offset, count);
                return a;
            }
            /// <summary>
            /// seek the position in <see cref="CryptoStream.cache"/>
            /// </summary>
            /// <param name="offset"></param>
            /// <param name="origin"></param>
            /// <returns></returns>
            public override long Seek(long offset, SeekOrigin origin)
            {
                return cache.Seek(offset, origin);
            }
            /// <summary>
            /// It will delete the content that out of the value parameter. 
            /// </summary>
            /// <param name="value">the edge of data.</param>
            public override void SetLength(long value)
            {
                cache.SetLength(value);
                if (lastFlush > value - 1)
                {
                    lastFlush = value - 1;
                }
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                switch (Crypto)
                {
                    case CryptoType.RSA2048:
                        ICryptor cryptor = new RSA256Cryptor();
                        if(Password == null)
                        {
                            var impl = new RSA2048Impl();
                            Password = new Key();
                            Password.PrivateKey = impl.MakePrivate();
                            Password.PublicKey = impl.MakePublic(Password.PrivateKey);
                        }
                        switch (Way)
                        {
                            case CryptWay.Encrypt:
                                using(MemoryStream temp = new MemoryStream())
                                {
                                    temp.Write(buffer, offset, count);
                                    cache.Write(cryptor.Encrypt(temp.ToArray(), Password.PublicKey));
                                }
                                FlushAsync();
                                break;
                            case CryptWay.Decrypt:
                                using (MemoryStream temp = new MemoryStream())
                                {
                                    temp.Write(buffer, offset, count);
                                    cache.Write(cryptor.Decrypt(temp.GetBuffer(), Password.PrivateKey));
                                }
                                FlushAsync();
                                break;
                        }
                        break;
                    case CryptoType.AES128:
                        cryptor = new AES128Cryptor();
                        if (Password == null)
                        {
                            byte[] rand = new byte[8];
                            new Random().NextBytes(rand);
                            rand = AESImpl.GetAesKey(rand, "");
                            Password = new Key();
                            Password.PublicKey = rand;
                            Password.PrivateKey = Password.PublicKey;
                        }
                        //MessageBox.Show(Way.ToString());
                        switch (Way)
                        {
                            case CryptWay.Encrypt:
                                using (MemoryStream temp = new MemoryStream())
                                {
                                    temp.Write(buffer, offset, count);
                                    //MessageBox.Show("Scissor Len:" + temp.Length);
                                    cache.Write(cryptor.Encrypt(temp.ToArray(), Password.PublicKey));
                                     
                                }
                                FlushAsync();
                                break;
                            case CryptWay.Decrypt:
                                using (MemoryStream temp = new MemoryStream())
                                {
                                    temp.Write(buffer, offset, count);
                                    cache.Write(cryptor.Decrypt(temp.ToArray(), Password.PrivateKey));
                                }
                                FlushAsync();
                                break;
                        }
                        break;
                    case CryptoType.SM2:
                        cryptor = new SM2Cryptor();
                        if (Password == null)
                        {
                            byte[][] pwd = new SM2Impl().makeKeyPair();
                            Password = new Key();
                            Password.PublicKey = pwd[0];
                            Password.PrivateKey = pwd[1];
                        }
                        switch (Way)
                        {
                            case CryptWay.Encrypt:
                                using (MemoryStream temp = new MemoryStream())
                                {
                                    temp.Write(buffer, offset, count);
                                    cache.Write(cryptor.Encrypt(temp.ToArray(), Password.PublicKey));
                                }
                                FlushAsync();
                                break;
                            case CryptWay.Decrypt:
                                using (MemoryStream temp = new MemoryStream())
                                {
                                    temp.Write(buffer, offset, count);
                                    cache.Write(cryptor.Decrypt(temp.ToArray(), Password.PrivateKey));
                                }
                                FlushAsync();
                                break;
                        }
                        break;
                    default:
                        throw new ArgumentException("Unsupported Algorithm.");
                 
                }
            }
        }
    }
}
