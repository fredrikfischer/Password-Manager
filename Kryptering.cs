using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;

namespace passwordmanager
{

    public class Kryptering
    {

        public AesCryptoServiceProvider kryptering;



        public Kryptering()
        {
            kryptering = new AesCryptoServiceProvider();

            kryptering.BlockSize = 128;
            kryptering.KeySize = 256;
            kryptering.GenerateIV();
            kryptering.GenerateKey();
            kryptering.Mode = CipherMode.CBC;
            kryptering.Padding = PaddingMode.PKCS7;
        }


        public string Encrypt(string clear_text, byte[] vaultKey, byte[] IV)
        {
            try
            {
                ICryptoTransform transform = kryptering.CreateEncryptor(vaultKey, IV);
                byte[] encryptedBytes = transform.TransformFinalBlock(ASCIIEncoding.ASCII.GetBytes(clear_text), 0, clear_text.Length);
                string encryptedString = Convert.ToBase64String(encryptedBytes);

                return encryptedString;
            }
            catch (Exception)
            {
                return "error";
            }



        }

        public string Decrypt(string cipher_text, byte[] vaultKey, byte[] IV)
        {
            try
            {
                ICryptoTransform transform = kryptering.CreateDecryptor(vaultKey, IV);
                byte[] encryptedBytes = Convert.FromBase64String(cipher_text);
                byte[] decryptedBytes = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                string decryptedString = ASCIIEncoding.ASCII.GetString(decryptedBytes);

                return decryptedString;
            }
            catch (Exception)
            {
                return "error";
            }



        }


    }
}