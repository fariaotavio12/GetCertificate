using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography.X509Certificates;
using iText.Signatures;

namespace Assinatura
{
    public class X509Certificate2Signature : IExternalSignature
    {
        private readonly X509Certificate2 certificate;

        public X509Certificate2Signature(X509Certificate2 certificate)
        {
            this.certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        public string GetHashAlgorithm()
        {
            return DigestAlgorithms.SHA256;
        }

        public string GetEncryptionAlgorithm()
        {
            return "RSA";
        }

        public byte[] Sign(byte[] message)
        {
            ISigner signer = SignerUtilities.GetSigner(GetEncryptionAlgorithm());

            signer.Init(true, GetPrivateAsymmetricKey());

            signer.BlockUpdate(message, 0, message.Length);

            return signer.GenerateSignature();
        }

        private AsymmetricKeyParameter GetPrivateAsymmetricKey()
        {
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(certificate.PrivateKey);
            AsymmetricKeyParameter privateKey = keyPair.Private;

            return privateKey;
        }

        public string GetDigestAlgorithmName()
        {
            throw new NotImplementedException();
        }

        public string GetSignatureAlgorithmName()
        {
            throw new NotImplementedException();
        }

        public ISignatureMechanismParams GetSignatureMechanismParameters()
        {
            throw new NotImplementedException();
        }
    }

}