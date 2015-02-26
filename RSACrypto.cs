using System;
using System.Security.Cryptography;  
using System.Text;
using System.Xml.Serialization;
using System.IO;

// <summary>  
// An asymmetric algorithm to publically encrypt and privately decrypt text data.
// Asymmetric encryption is only designed for encrypting data smaller than it's key size. So always use assymetric to exchange a symmetric key.
// Using PKCS#1 v1.5 padding
// </summary>  

namespace RSACryptoService
{
    public class RSACrypto
    {
        private RSACryptoServiceProvider csp;
        private RSAParameters privateKey;
        private RSAParameters publicKey;

        /// <summary>  
        /// Constructor with optional parameter for bit-size
        /// </summary> 
        public RSACrypto(int bit = 2048)
        {
            csp = new RSACryptoServiceProvider(bit);

            privateKey = csp.ExportParameters(true);
            publicKey = csp.ExportParameters(false);
        }

        /// <summary>  
        /// Encrypt byte array
        /// </summary> 
        public byte[] Encrypt(byte[] data)
        {
            return encryptData(data, csp);
        }

        /// <summary>  
        /// Encrypt byte array with XML-string containing the RSAParameters
        /// </summary> 
        public byte[] Encrypt(byte[] data, string XMLRSAParameters)
        {
            RSACryptoServiceProvider internalCsp = new RSACryptoServiceProvider();
            internalCsp.FromXmlString(XMLRSAParameters);

            return encryptData(data, internalCsp);
        }

        /// <summary>  
        /// Encrypt byte array with RSAParameters
        /// </summary> 
        public byte[] Encrypt(byte[] data, RSAParameters parameters)
        {
            RSACryptoServiceProvider internalCsp = new RSACryptoServiceProvider();
            internalCsp.ImportParameters(parameters);

            return encryptData(data, internalCsp);
        }

        /// <summary>  
        /// Private encrypting-method
        /// </summary> 
        private byte[] encryptData(byte[] data, RSACryptoServiceProvider internalCsp)
        {
            return internalCsp.Encrypt(data, false);
        }

        /// <summary>  
        /// Decrypt byte array
        /// </summary> 
        public byte[] Decrypt(byte[] data)
        {
            return decryptData(data, csp);
        }

        /// <summary>  
        /// Decrypt byte array with XML-string containing the RSAParameters
        /// </summary> 
        public byte[] Decrypt(byte[] data, string XMLRSAParameters)
        {
            RSACryptoServiceProvider internalCsp = new RSACryptoServiceProvider();
            internalCsp.FromXmlString(XMLRSAParameters);

            return decryptData(data, internalCsp);
        }

        /// <summary>  
        /// Encrypt byte array with RSAParameters
        /// </summary> 
        public byte[] Decrypt(byte[] data, RSAParameters parameters) {
            RSACryptoServiceProvider internalCsp = new RSACryptoServiceProvider();
            internalCsp.ImportParameters(parameters);

            return decryptData(data, internalCsp);
        }

        /// <summary>  
        /// Private encrypting-method
        /// </summary> 
        private byte[] decryptData(byte[] data, RSACryptoServiceProvider internalCsp)
        {
            if (internalCsp.PublicOnly) throw new ArgumentException("Please provider proper parameters containing a private key");

            return internalCsp.Decrypt(data, false);
        }

        /// <summary>  
        /// Private method for serializing RSAParameters to XML-string
        /// </summary> 
        private string RSAParametersToXML(RSAParameters key)
        {
            XmlSerializer serializer = new XmlSerializer(key.GetType());

            using (StringWriter textWriter = new StringWriter())
            {
                serializer.Serialize(textWriter, key);
                return textWriter.ToString();
            }   
        }

        /// <summary>  
        /// Get private key as RSAParameters
        /// </summary>
        public RSAParameters getPrivateKey()
        {
            return privateKey;
        }

        /// <summary>  
        /// Get public key as RSAParameters
        /// </summary>
        public RSAParameters getPublicKey()
        {
            return publicKey;
        }

        /// <summary>  
        /// Get private key as XML-string
        /// </summary>
        public string getPrivateKeyXML()
        {
            return RSAParametersToXML(privateKey);   
        }

        /// <summary>  
        /// Get public key as XML-string
        /// </summary>
        public string getPublicKeyXML()
        {
            return RSAParametersToXML(publicKey);
        }

    }
}