using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CreativeCode.JWK.KeyParts;
using CreativeCode.JWS.TypeConverters;
using Newtonsoft.Json;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWS
{
    [JsonConverter(typeof(JwsConverter))]
    public class JWS
    {
        // JWS parts
        [JWSConverterAttribute(typeof(ProtectedJoseHeaderConverter))]
        internal IEnumerable<ProtectedJoseHeader> ProtectedJoseHeaders { get; }
        internal byte[] JwsPayload { get; }    // Raw value, NOT base64 encoded
        internal IEnumerable<byte[]> JwsSignatures { get; private set; }  // Raw value, NOT base64 encoded
        
        public JWS(IEnumerable<ProtectedJoseHeader> protectedJoseHeaders, byte[] jwsPayload)
        {
            if (protectedJoseHeaders is null)
                throw new ArgumentNullException("protectedJoseHeaders MUST be provided");
            if (jwsPayload is null)
                throw new ArgumentNullException("jwsPayload MUST be provided");
            if (!protectedJoseHeaders.Any())
                throw new ArgumentException("At least one protected JoseHeader MUST be provided");
            if (jwsPayload.Length == 0)
                throw new ArgumentException("jwsPayload MUST NOT be empty");

            ProtectedJoseHeaders = protectedJoseHeaders;
            JwsPayload = jwsPayload;
        }

        #region Signatures

        public void CalculateSignature()
        {
            var signatures = new List<byte[]>();
            foreach (var protectedJoseHeader in ProtectedJoseHeaders)
            {
                if (protectedJoseHeader.JWK.KeyType == KeyType.RSA)
                    signatures.Add(RSASSA_PKCS1_v1_5_Signature(protectedJoseHeader));
                else if (protectedJoseHeader.JWK.KeyType == KeyType.EllipticCurve)
                    signatures.Add(ECDSA_Signature(protectedJoseHeader));
                else if (protectedJoseHeader.JWK.KeyType == KeyType.OCT)
                    signatures.Add(HMACSignature(protectedJoseHeader));
                else
                    throw new InvalidOperationException($"Cannot calculate signature for KeyType '{protectedJoseHeader.JWK.KeyType.Type}'");
            }

            JwsSignatures = signatures;
        }
        
        private byte[] SigningInput(ProtectedJoseHeader protectedJoseHeader)
        {
            var protectedJoseHeaderJson = new ProtectedJoseHeaderConverter().Serialize(protectedJoseHeader);
            return Encoding.ASCII.GetBytes(Base64urlEncode(Encoding.UTF8.GetBytes(protectedJoseHeaderJson)) + "." + Base64urlEncode(JwsPayload));
        }

        // RSASSA-PKCS1-v1_5 using SHA-256 / SHA-384 / SHA-512
        private byte[] RSASSA_PKCS1_v1_5_Signature(ProtectedJoseHeader protectedJoseHeader)
        {
            var rsaParameters = new RSAParameters
            {
                D = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterD]),
                Exponent = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterE]),
                Modulus = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterN]),
                P = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterP]),
                Q = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterQ]),
                DP = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterDP]),
                DQ = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterDQ]),
                InverseQ = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.RSAKeyParameterQI]),
            };
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            HashAlgorithmName sha;
            switch (protectedJoseHeader.Algorithm.Name)
            {
                case "RS256":
                    sha = HashAlgorithmName.SHA256;
                    break;
                case "RS384":
                    sha = HashAlgorithmName.SHA384;
                    break;
                case "RS512":
                    sha = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new CryptographicException("Could not create signature. Found invalid RSA algorithm: " + protectedJoseHeader.Algorithm.Name);
            }
            
            return rsa.SignData(SigningInput(protectedJoseHeader),sha, RSASignaturePadding.Pkcs1);
        }
        
        // ECDSA using (P-256 / P-384 / P-521) and SHA-256 / SHA-384 / SHA-512
        private byte[] ECDSA_Signature(ProtectedJoseHeader protectedJoseHeader)
        {
            var ecParameters = new ECParameters()
            {
                Curve = TranslateCurve(protectedJoseHeader.JWK.Algorithm),
                D = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.ECKeyParameterD]),
                Q = new ECPoint { X = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.ECKeyParameterX]), Y = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.ECKeyParameterY]) }
            };
            ecParameters.Validate();
            var ecdsa = ECDsa.Create(ecParameters);
            
            HashAlgorithmName sha;
            var keyLength = protectedJoseHeader.Algorithm.Name.Split(new string[] { "ES" }, StringSplitOptions.None)[1]; // Algorithm = 'ES' + Keylength
            switch (keyLength)
            {
                case "256":
                    sha = HashAlgorithmName.SHA256;
                    break;
                case "384":
                    sha = HashAlgorithmName.SHA384;
                    break;
                case "512":
                    sha = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new ArgumentException("Could not create ECCurve based on algorithm: " + protectedJoseHeader.Algorithm.Name);
            }

            return ecdsa.SignData(SigningInput(protectedJoseHeader), sha);
        }
        
        // Workaround: Using ECCurve.CreateFromFriendlyName results in a PlatformException for NIST curves
        private ECCurve TranslateCurve(Algorithm algorithm)
        {
            if(algorithm == Algorithm.ES256)
                return ECCurve.CreateFromOid(new Oid("1.2.840.10045.3.1.7"));
            if (algorithm == Algorithm.ES384)
                return ECCurve.CreateFromOid(new Oid("1.3.132.0.34"));
            if (algorithm == Algorithm.ES512)
                return ECCurve.CreateFromOid(new Oid("1.3.132.0.35"));
            else
                throw new InvalidOperationException($"ECKeyStore - Cannot create curve for algorithm '{algorithm}'");
        }
        
        // HMAC using SHA-256 / SHA-384 / SHA-512
        private byte[] HMACSignature(ProtectedJoseHeader protectedJoseHeader)
        {
            HMAC hmac;
            var key = Base64urlDecode(protectedJoseHeader.JWK.KeyParameters[KeyParameter.OctKeyParameterK]); // key is padded by HMACSHA* implementation to provide add least a security of 64 bytes
            switch (protectedJoseHeader.Algorithm.Name)
            {
                case "HS256":
                    hmac = new HMACSHA256(key);
                    break;
                case "HS384":
                    hmac = new HMACSHA384(key);
                    break;
                case "HS512":
                    hmac = new HMACSHA512(key);
                    break;
                default:
                    throw new CryptographicException("Could not create HMAC key based on algorithm " + protectedJoseHeader.Algorithm.Name + " (Could not parse expected SHA version)");
            }

            return hmac.ComputeHash(SigningInput(protectedJoseHeader));
        }

        #endregion

        #region Serialization

        public string Export()
        {
            return JsonConvert.SerializeObject(this);
        }

        #endregion

    }

}
