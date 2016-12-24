using System;
using System.IO;
using System.Xml;
using System.Text;
using System.Linq;
using System.Xml.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace TORComm.Security.RSA
{
    public class KeyStorageProvider
    {
        public String KeyFilePath;

        private Byte[] StoredSalt;
        private Byte[] IntermediateKey;
        private RSACryptoServiceProvider KeyObject;

        private void DeriveIntermediateKey(Byte[] KeyBytes)
        {
            this.IntermediateKey = KeyBytes;
            SHA512CryptoServiceProvider sha = new SHA512CryptoServiceProvider();
            for(int i = 0; i < 10000; i++)
            {
                ArrayList CombinedValues = new ArrayList();
                CombinedValues.AddRange(this.StoredSalt);
                CombinedValues.AddRange(this.IntermediateKey);
                this.IntermediateKey = sha.ComputeHash((Byte[])CombinedValues.ToArray(typeof(byte)));
            }
            sha.Dispose();
        }

        private Byte[] DeriveEncryptionKey()
        {
            if(this.IntermediateKey != null)
            {
                Byte[] DerivedKey = this.IntermediateKey;
                SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();
                for(int i = 0; i < 10000; i++)
                {
                    DerivedKey = sha.ComputeHash(DerivedKey);
                }
                sha.Dispose();
                return DerivedKey;
            }
            else
            {
                throw new System.InvalidOperationException("Unable to derive encryption key without first deriving the intermediary.");
            }
        }

        private Byte[] DeriveSigningKey()
        {
            if(this.IntermediateKey != null)
            {
                Byte[] DerivedKey = this.IntermediateKey;
                SHA512CryptoServiceProvider sha = new SHA512CryptoServiceProvider();
                for(int i = 0;i < 10000; i++)
                {
                    DerivedKey = sha.ComputeHash(DerivedKey);
                }
                sha.Dispose();
                return DerivedKey;
            }
            else
            {
                throw new System.InvalidOperationException("Unable to derive signing key without first deriving the intermediary.");
            }
        }

        private void SaveKeyObject()
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.Key = this.DeriveEncryptionKey();
            aes.GenerateIV();
            ArrayList MetaConstructor = new ArrayList();
            MetaConstructor.AddRange(this.StoredSalt);
            MetaConstructor.AddRange(aes.IV);
            String MetaObject = Convert.ToBase64String((Byte[])MetaConstructor.ToArray(typeof(byte)));
            String DataObject = String.Empty;
            using (MemoryStream mstream = new MemoryStream())
            {
                using (CryptoStream cstream = new CryptoStream(mstream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (BinaryWriter writer = new BinaryWriter(cstream))
                    {
                        writer.Write(this.KeyObject.ExportCspBlob(true));
                    }
                }
                DataObject = Convert.ToBase64String(mstream.ToArray());
            }
            aes.Dispose();
            String IntegrityObject = this.ComputeHMACUsingSigningKey(DataObject);
            XDocument KeyFile = new XDocument(new XElement("SecureKeyFile",
                                                    new XElement("Meta", MetaObject),
                                                    new XElement("KeyData", DataObject),
                                                    new XElement("IntegrityCheck", IntegrityObject)));
            KeyFile.Save(this.KeyFilePath);
        }

        public bool LoadSavedKey(String PlaintextKey)
        {
            bool ReturnValue = false;
            if(File.Exists(this.KeyFilePath))
            {
                this.StoredSalt = new Byte[16];
                Byte[] InitVector = new Byte[16];
                XmlDocument KeyFile = new XmlDocument();
                KeyFile.Load(this.KeyFilePath);
                Byte[] MetaObject = Convert.FromBase64String(KeyFile.SelectSingleNode("SecureKeyFile/Meta").InnerText);
                Array.Copy(MetaObject, this.StoredSalt, this.StoredSalt.Length);
                Array.Copy(MetaObject.Skip(16).ToArray<Byte>(), InitVector, InitVector.Length);
                this.DeriveIntermediateKey(Encoding.UTF8.GetBytes(PlaintextKey));
                String StoredKeyData = KeyFile.SelectSingleNode("SecureKeyFile/KeyData").InnerText;
                if (KeyFile.SelectSingleNode("SecureKeyFile/IntegrityCheck").InnerText == this.ComputeHMACUsingSigningKey(StoredKeyData))
                {
                    AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                    aes.Key = this.DeriveEncryptionKey();
                    aes.IV = InitVector;
                    using (MemoryStream mstream = new MemoryStream())
                    {
                        using (CryptoStream cstream = new CryptoStream(mstream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            using (BinaryWriter writer = new BinaryWriter(cstream))
                            {
                                writer.Write(Convert.FromBase64String(StoredKeyData));
                            }
                        }
                        this.KeyObject = new RSACryptoServiceProvider();
                        this.KeyObject.ImportCspBlob(mstream.ToArray());
                    }
                    aes.Dispose();
                    ReturnValue = true;
                    this.SaveKeyObject();
                }
            }
            return ReturnValue;
        }

        public void CreateNewKey(String PlaintextKey)
        {
            RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
            this.KeyObject = new RSACryptoServiceProvider(4096);
            this.StoredSalt = new Byte[16];
            RNG.GetNonZeroBytes(this.StoredSalt);
            this.DeriveIntermediateKey(Encoding.UTF8.GetBytes(PlaintextKey));
            this.SaveKeyObject();
            RNG.Dispose();
        }

        public String ComputeHMACUsingSigningKey(String InputString, bool AsBase64=false)
        {
            HMACSHA512 hmac = new HMACSHA512();
            hmac.Key = this.DeriveSigningKey();
            String IntegrityObject = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(InputString)));
            hmac.Dispose();
            if(!(AsBase64))
            {
                IntegrityObject = IntegrityObject.Remove('=');
            }
            return IntegrityObject;
        }

        public RSACryptoServiceProvider GetRSAKeys()
        {
            RSACryptoServiceProvider NewKey = null;
            if(this.KeyObject != null)
            {
                NewKey = new RSACryptoServiceProvider();
                NewKey.ImportCspBlob(this.KeyObject.ExportCspBlob(true));
            }
            return NewKey;
        }

        public KeyStorageProvider()
        {
            this.KeyFilePath = Path.Combine(TORComm.Active.StoragePath, "KeyFile");
        }
    }

    static class CryptoInterface
    {
        public static String CreateKeyStorageObject(Byte[] EncryptionKey, Byte[] InitVector, RSACryptoServiceProvider KeyObject=null)
        {
            String ReturnValue = String.Empty;
            if(KeyObject == null)
            {
                KeyObject = TORComm.Active.KeyStore.GetRSAKeys();
            }
            if(KeyObject != null)
            {
                ArrayList StorageArray = new ArrayList();
                StorageArray.AddRange(InitVector);
                StorageArray.AddRange(EncryptionKey);
                ReturnValue = Convert.ToBase64String(KeyObject.Encrypt((Byte[])StorageArray.ToArray(typeof(byte)), true));
            }
            return ReturnValue;
        }

        public static String GetSHA512Signature(Byte[] HashValue, RSACryptoServiceProvider KeyObject=null)
        {
            String ReturnValue = String.Empty;
            if(KeyObject == null)
            {
                KeyObject = TORComm.Active.KeyStore.GetRSAKeys();
            }
            if(KeyObject != null)
            {
                ReturnValue = Convert.ToBase64String(KeyObject.SignHash(HashValue, CryptoConfig.MapNameToOID("SHA512")));
            }
            return ReturnValue;
        }

        public static String EncryptString(String InputString, RSACryptoServiceProvider KeyObject=null)
        {
            String ReturnValue = String.Empty;
            if (KeyObject == null)
            {
                KeyObject = TORComm.Active.KeyStore.GetRSAKeys();
            }
            // Ensure the key was loaded properly
            if(KeyObject != null)
            {
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                aes.GenerateKey();
                aes.GenerateIV();
                String EncryptedData = String.Empty;
                using (MemoryStream mstream = new MemoryStream())
                {
                    using (CryptoStream cstream = new CryptoStream(mstream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (BinaryWriter writer = new BinaryWriter(cstream))
                        {
                            writer.Write(Encoding.UTF8.GetBytes(InputString));
                        }
                    }
                    EncryptedData = Convert.ToBase64String(mstream.ToArray());
                }
                XDocument SecureContent = new XDocument(new XElement("SecureContent",
                                                            new XElement("KeyStorage", CreateKeyStorageObject(aes.Key, aes.IV, KeyObject)),
                                                            new XElement("EncryptedData", EncryptedData)));
                XDocument FinalDocument = new XDocument(new XElement("DataProtectionDocument",
                                                            new XElement("ProtectedArea", SecureContent.Root)));
                XElement ProtectedArea = (XElement)(from Node in FinalDocument.Descendants("ProtectedArea")
                                                      where Node.Name == "ProtectedArea"
                                                      select Node).FirstOrDefault();
                XmlDocument ConvertedProtectedArea = new XmlDocument();
                ConvertedProtectedArea.LoadXml(ProtectedArea.ToString());
                String IntegrityCheck = TORComm.Active.KeyStore.ComputeHMACUsingSigningKey(ConvertedProtectedArea.OuterXml, true);
                String StringSignature = GetSHA512Signature(Convert.FromBase64String(IntegrityCheck));
                FinalDocument.Descendants().FirstOrDefault().Add(new XElement("IntegrityCheck", IntegrityCheck),
                                                                    new XElement("DocumentSignature", StringSignature));
                ReturnValue = FinalDocument.ToString();
            }
            return ReturnValue;
        }

        public static String DecryptString(String InputString, RSACryptoServiceProvider KeyObject = null)
        {
            String ReturnValue = String.Empty;
            if(KeyObject == null)
            {
                KeyObject = TORComm.Active.KeyStore.GetRSAKeys();
            }
            // Ensure the key was loaded properly
            if (KeyObject != null)
            {
                XmlDocument ProtectedDocument = new XmlDocument();
                ProtectedDocument.LoadXml(InputString);
                XmlNode ProtectedArea = ProtectedDocument.SelectSingleNode("DataProtectionDocument/ProtectedArea");
                String DerivedHashString = TORComm.Active.KeyStore.ComputeHMACUsingSigningKey(ProtectedArea.OuterXml, true);
                // Verify that the protected area has not been tampered with or otherwise modified before continuing with decryption
                if (ProtectedDocument.SelectSingleNode("DataProtectionDocument/IntegrityCheck").InnerText == DerivedHashString)
                {
                    // Validate that the signature matches our signature.  This almost certainly means that the document has not been modified since we created it.
                    Byte[] DecodedSignature = Convert.FromBase64String(ProtectedDocument.SelectSingleNode("DataProtectionDocument/DocumentSignature").InnerText);
                    if(Convert.FromBase64String(GetSHA512Signature(Convert.FromBase64String(DerivedHashString), KeyObject)).SequenceEqual(DecodedSignature))
                    {
                        // Everything looks good, start the decryption process.
                        XmlDocument SecureContent = new XmlDocument();
                        SecureContent.LoadXml(ProtectedArea.InnerXml);
                        Byte[] InitVector = new byte[16];
                        Byte[] KeyStorageObject = KeyObject.Decrypt(Convert.FromBase64String(SecureContent.SelectSingleNode("SecureContent/KeyStorage").InnerText), true);
                        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                        Array.Copy(KeyStorageObject, InitVector, InitVector.Length);
                        aes.Key = KeyStorageObject.Skip(InitVector.Length).ToArray();
                        aes.IV = InitVector;
                        using (MemoryStream mstream = new MemoryStream())
                        {
                            using (CryptoStream cstream = new CryptoStream(mstream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                using (BinaryWriter writer = new BinaryWriter(cstream))
                                {
                                    writer.Write(Convert.FromBase64String(SecureContent.SelectSingleNode("SecureContent/EncryptedData").InnerText));
                                }
                            }
                            ReturnValue = System.Text.Encoding.UTF8.GetString(mstream.ToArray());
                        }
                    }
                }
            }
            return ReturnValue;
        }
    }

    public static class Extract
    {
        public static TORComm.Components.Security.KeyConversionAssistant KeyFromArray(int i, String[] s)
        {
            List<String> KeyComponentList = new List<string>();
            TORComm.Components.Security.KeyConversionAssistant ConversionHelper = new Components.Security.KeyConversionAssistant(i, s);
            while (!(ConversionHelper.SplitMessage[ConversionHelper.index].Contains("END RSA PUBLIC KEY")))
            {
                KeyComponentList.Add(ConversionHelper.SplitMessage[++ConversionHelper.index]);
            }
            String KeyString = String.Join("\n", KeyComponentList.ToArray());
            if (KeyString.Contains("BEGIN RSA PUBLIC KEY") && KeyString.Contains("END RSA PUBLIC KEY"))
            {
                ConversionHelper.ConvertedKey = CSPKeyConvert.PublicKeyFromPEM(KeyString);
            }
            ConversionHelper.index++;
            return ConversionHelper;
        }
    }

    public static class CSPKeyConvert
    {
        public static Byte[] FromPEMToDER(String PEMEncodedString)
        {
            // Clean the -----BEGIN RSA <TYPE> KEY----- and -----END RSA <TYPE> KEY----- lines included in PEM strings
            List<String> SplitPEMString = PEMEncodedString.Split(new String[] { "\r\n", "\n" }, StringSplitOptions.None).Skip(1).ToList();
            SplitPEMString.RemoveAt(SplitPEMString.Count - 1);
            return Convert.FromBase64String(String.Join(String.Empty, SplitPEMString.ToArray()));
        }

        public static RSACryptoServiceProvider PublicKeyFromDER(Byte[] DERByteArray)
        {
            RSACryptoServiceProvider NewKey = new RSACryptoServiceProvider();
            RSAParameters KeyParams = NewKey.ExportParameters(false);
            KeyParams.Modulus = DERByteArray;
            NewKey.ImportParameters(KeyParams);
            return NewKey;
        }

        public static RSACryptoServiceProvider PublicKeyFromPEM(String PEMEncodedString)
        {
            if(PEMEncodedString.Contains("BEGIN RSA PUBLIC KEY"))
            {
                return PublicKeyFromDER(FromPEMToDER(PEMEncodedString));
            }
            return null;
        }

    }
}