using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Cifrado_RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            RsaEncryption rsa = new RsaEncryption();
            string cypher = "";
            
            //Public Key
            Console.WriteLine("////////////////////////////////////////////////////");
            Console.WriteLine($"Public key: \n {rsa.GetPublicKey()}");
            Console.WriteLine("////////////////////////////////////////////////////");

            //Input message to be encrypted
            Console.WriteLine("Input message to be encrypted: ");
            string text = Console.ReadLine();
            
            //If the string isnt null or empty the message is encrypted
            if (!string.IsNullOrEmpty(text))
            {
                Console.WriteLine("////////////////////////////////////////////////////");
                cypher = rsa.Encrypt(text); //Message is encrypted
                Console.WriteLine($"Encrypted message: {cypher}"); //Encrypted Message
                Console.WriteLine("////////////////////////////////////////////////////");
            }

            //Message in decrypted to plain text
            Console.WriteLine("Decrypted message: ");
            string plainText = rsa.Decrypt(cypher);
            Console.WriteLine(plainText);

        }
    }
    
    public class RsaEncryption
    {
        //Encryption for 2048 bits
        private static RSACryptoServiceProvider _csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RsaEncryption()
        {
            _privateKey = _csp.ExportParameters(true);
            _publicKey = _csp.ExportParameters(false);
        }

        //Extract public key information
        public string GetPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw,_publicKey);
            return sw.ToString();
        }

        public string Encrypt(string plainText)
        {
            _csp = new RSACryptoServiceProvider();
            _csp.ImportParameters(_publicKey); //Using public key to encrypt the data
            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = _csp.Encrypt(data,false);
            return Convert.ToBase64String(cypher);
        }

        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            _csp.ImportParameters(_privateKey); //Using private key to decrypt
            var plainText = _csp.Decrypt(dataBytes, false);
            return Encoding.Unicode.GetString(plainText);
        }
    }
}