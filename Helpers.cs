using System;
using System.IO;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Saft_client
{
    public class Helpers
    {
        /// <summary>
        /// create the header
        /// 
        /// translated from https://www.portugal-a-programar.pt/forums/topic/57734-utilizar-webservices-da-at/?page=298
        /// 
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static string CreateHeader(X509Certificate2 certificate, string userName, string password)
        {
            string header = string.Empty;

            string createdDate = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
            byte[] created = Encoding.UTF8.GetBytes(createdDate);


            byte[] key = new Guid().ToByteArray();

            // new rsa with public key
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(certificate.PublicKey.Key.ToXmlString(false));


            byte[] nonce = rsa.Encrypt(key, false);

            AesCryptoServiceProvider cipher = new AesCryptoServiceProvider();
            cipher.Mode = CipherMode.ECB;
            cipher.Key = key;

            byte[] passwordEncrypted = Helpers.EncryptStringToBytes_Aes(password, cipher);

            // fields to be included in header
            string usernameHeader = userName;
            string passwordHeader = Convert.ToBase64String(passwordEncrypted);
            string nonceHeader = Convert.ToBase64String(nonce);
            string createdHeader = Convert.ToBase64String(created);

            header = @"<?xml version=""1.0"" encoding=""utf-8"" standalone = ""no""?>
<S:Envelope xmlns:S=""http://schemas.xmlsoap.org/soap/envelope/"">
<S:Header>
<wss:Security xmlns:wss=""http://schemas.xmlsoap.org/ws/2002/12/secext"">
<wss:UsernameToken> 
<wss:Username>" + usernameHeader + "</wss:Username>" +
"<wss:Password>" + passwordHeader + "</wss:Password>" +
"<wss:Nonce>" + nonceHeader + "</wss:Nonce>" +
"<wss:Created>" + createdHeader + "</wss:Created>" +
"</wss:UsernameToken>" +
"</wss:Security>" +
"</S:Header>";

            return header;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="text">to be encrypted</param>
        /// <param name="certificateFilePath">certificade pfx</param>
        /// <param name="password">certificated password</param>
        /// <returns></returns>
        public static string EncryptUsingRSA(string text, string certificateFilePath, string password = "") // String Implements IEncryptionServices.EncryptUsingRSA
        {
            if (!text.IsBase64())
            {
                throw new ArgumentException("Input must be base 64 string", nameof(text));
            }

            X509Certificate2 certificate = new X509Certificate2(certificateFilePath, password);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.FromXmlString(certificate.PublicKey.Key.ToXmlString(false));
            byte[] key = csp.Encrypt(Convert.FromBase64String(text), false);
            string cypherText = Convert.ToBase64String(key);
            return cypherText;
        }

        /// <summary>
        /// encrypt key using RSA
        /// </summary>
        /// <param name="text">to be encrypted</param>
        /// <param name="certificate">certificate store</param>
        /// <returns></returns>
        public static string EncryptUsingRSA(string text, X509Certificate2 certificate)
        {
            if (!text.IsBase64())
            {
                throw new ArgumentException("Input must be base 64 string", nameof(text));
            }
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.FromXmlString(certificate.PublicKey.Key.ToXmlString(false));
            byte[] key = csp.Encrypt(Convert.FromBase64String(text), false);
            string cypherText = Convert.ToBase64String(key);

            return cypherText;
        }


        /// <summary>
        /// taken from https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aescryptoserviceprovider?view=netframework-4.7.2
        /// </summary>
        /// <param name="plainText">tewxt to be crypted</param>
        /// <param name="aesAlg">algoritm to encrypt data</param>
        /// <returns>crypt data</returns>
        public static byte[] EncryptStringToBytes_Aes(string plainText, AesCryptoServiceProvider aesAlg)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (aesAlg.Key == null || aesAlg.Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (aesAlg.IV == null || aesAlg.IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;


            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor();

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        /// <summary>
        /// taken from https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aescryptoserviceprovider?view=netframework-4.7.2
        /// </summary>
        /// <param name="cipherText">encrypt text</param>
        /// <param name="aesAlg">algrithm set to uncrypt data</param>
        /// <returns>uncrypt text</returns>
        public static string DecryptStringFromBytes_Aes(byte[] cipherText, AesCryptoServiceProvider aesAlg)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (aesAlg.Key == null || aesAlg.Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (aesAlg.IV == null || aesAlg.IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor();

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            return plaintext;
        }


        /// <summary>
        /// Taken from https://dotnetcodr.com/2015/06/08/https-and-x509-certificates-in-net-part-4-working-with-certificates-in-code/
        /// </summary>
        /// <param name="sslCert"></param>
        public static void  InstallDerivedCertificate(X509Certificate2 sslCert)
        {

            X509Store personalStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                personalStore.Open(OpenFlags.ReadWrite);
                personalStore.Add(sslCert);
            }
            catch (Exception ex)
            {
                Console.WriteLine("SSL certificate import failed: " + ex.ToString());
            }
            finally
            {
                personalStore.Close();
            }
        }


        /// <summary>
        /// unistall certicate from store
        /// </summary>
        /// <param name="subjectCN"></param>
        public static void UninstallCertificate(string subjectCN)
        {
            X509Store personalStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                personalStore.Open(OpenFlags.ReadWrite);
                X509Certificate2Collection findResult = personalStore.Certificates.Find(X509FindType.FindBySubjectName, subjectCN, false);
                if (findResult.Count > 0)
                {
                    foreach (X509Certificate2 item in findResult)
                    {
                        personalStore.Remove(item);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("SSL certificate import failed: " + ex.ToString());
            }
            finally
            {
                personalStore.Close();
            }

            X509Store computerCaStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            try
            {
                computerCaStore.Open(OpenFlags.ReadWrite);
                X509Certificate2Collection findResult = computerCaStore.Certificates.Find(X509FindType.FindBySubjectName, "RootCertReloaded", false);
                if (findResult.Count > 0)
                {
                    foreach (X509Certificate2 item in findResult)
                    {
                        computerCaStore.Remove(item);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Root certificate uninstall failed: " + ex.ToString());
            }
            finally
            {
                computerCaStore.Close();
            }
        }


        /// <summary>
        /// list all the certifates in personal store
        /// </summary>
        public static  void ListCertifactes()
        {
            X509Store computerCaStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                computerCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = computerCaStore.Certificates;
                foreach (X509Certificate2 cert in certificatesInStore)
                {
                    Console.WriteLine(cert.GetExpirationDateString());
                    Console.WriteLine(cert.Issuer);
                    Console.WriteLine(cert.GetEffectiveDateString());
                    Console.WriteLine(cert.GetNameInfo(X509NameType.SimpleName, true));
                    Console.WriteLine(cert.HasPrivateKey);
                    Console.WriteLine(cert.SubjectName.Name);
                    Console.WriteLine("-----------------------------------");
                }
            }
            finally
            {
                computerCaStore.Close();
            }
        }


        /// <summary>
        /// list the content of certificate
        /// </summary>
        /// <param name="certificate"></param>
        public static void CertificateDetails(X509Certificate2 certificate)
        {

            string subjectName = certificate.Subject;
            string subjectDName = certificate.SubjectName.Name;

            string expirationDate = certificate.GetExpirationDateString();
            string issuer = certificate.Issuer;
            string effectiveDateString = certificate.GetEffectiveDateString();
            string nameInfo = certificate.GetNameInfo(X509NameType.SimpleName, true);
            bool hasPrivateKey = certificate.HasPrivateKey;

            Console.WriteLine(subjectName);
            Console.WriteLine(subjectDName);
            Console.WriteLine(expirationDate);
            Console.WriteLine(issuer);
            Console.WriteLine(effectiveDateString);
            Console.WriteLine(nameInfo);
            Console.WriteLine(hasPrivateKey);
        }
    }


    /// <summary>
    /// validate is is a Bas64 string
    /// </summary>
    public static class Extensions
    {
        public static bool IsBase64(this string str)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(str);
                return (str.Replace(" ", "").Length % 4 == 0);
            }
            catch (Exception)
            {
                return false;
            }
        }

    }
}
