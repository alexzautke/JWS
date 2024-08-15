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

        public static bool VerifySignature(JWK.JWK jwk, byte[] data, byte[] signature)
        {
            switch (jwk.KeyType.Type)
            {
                case "RSA": 
                    return VerifyRSASSA_PKCS1_v1_5_Signature(jwk, data, signature);
                case "EC":
                    return VerifyEcdsaSignature(jwk, data, signature);
                case "OCT":
                    return VerifyHmacSignature(jwk, data, signature);
                default:
                    throw new InvalidOperationException("");
            }
        }
        
        internal static byte[] SigningInput(ProtectedJoseHeader protectedJoseHeader, byte[] payload)
        {
            var protectedJoseHeaderJson = new ProtectedJoseHeaderConverter().Serialize(protectedJoseHeader);
            return Encoding.ASCII.GetBytes(Base64urlEncode(Encoding.UTF8.GetBytes(protectedJoseHeaderJson)) + "." + Base64urlEncode(payload));
        }
        
        #endregion Signatures
        
        #region RSA

        // RSASSA-PKCS1-v1_5 using SHA-256 / SHA-384 / SHA-512
        private byte[] RSASSA_PKCS1_v1_5_Signature(ProtectedJoseHeader protectedJoseHeader)
        {
            var rsa = CreateRsaKeyFromJWK(protectedJoseHeader.JWK);
            var sha = TranslateRsaHashAlgorithm(protectedJoseHeader.Algorithm);
            
            return rsa.SignData(SigningInput(protectedJoseHeader, JwsPayload),sha, RSASignaturePadding.Pkcs1);
        }

        private static bool VerifyRSASSA_PKCS1_v1_5_Signature(JWK.JWK jwk, byte[] data, byte[] signature)
        {
            var rsa = CreateRsaKeyFromJWK(jwk);
            var sha = TranslateRsaHashAlgorithm(jwk.Algorithm);
            return rsa.VerifyData(data, signature, sha, RSASignaturePadding.Pkcs1);
        }

        private static HashAlgorithmName TranslateRsaHashAlgorithm(Algorithm algorithm)
        {
            HashAlgorithmName sha;
            switch (algorithm.Name)
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
                    throw new CryptographicException("Could not create signature. Found invalid RSA algorithm: " + algorithm.Name);
            }

            return sha;
        }

        private static RSACryptoServiceProvider CreateRsaKeyFromJWK(JWK.JWK jwk)
        {
            var rsaParameters = new RSAParameters();
            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterD, out var dValue))
            {
                rsaParameters.D = Base64urlDecode(dValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterE, out var eValue))
            {
                rsaParameters.Exponent = Base64urlDecode(eValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterN, out var nValue))
            {
                rsaParameters.Modulus = Base64urlDecode(nValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterP, out var pValue))
            {
                rsaParameters.P = Base64urlDecode(pValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterQ, out var qValue))
            {
                rsaParameters.Q = Base64urlDecode(qValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterDP, out var dpValue))
            {
                rsaParameters.DP = Base64urlDecode(dpValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterDQ, out var dqValue))
            {
                rsaParameters.DQ = Base64urlDecode(dqValue);
            }

            if (jwk.KeyParameters.TryGetValue(KeyParameter.RSAKeyParameterQI, out var qiValue))
            {
                rsaParameters.InverseQ = Base64urlDecode(qiValue);
            }

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            return rsa;
        }
        
        #endregion RSA
        
        #region ECDSA
        // ECDSA using (P-256 / P-384 / P-521) and SHA-256 / SHA-384 / SHA-512
        private byte[] ECDSA_Signature(ProtectedJoseHeader protectedJoseHeader)
        {
            var ecdsa = CreateEcKeyFromJWK(protectedJoseHeader.JWK);
            var sha = TranslateEcHashAlgorithm(protectedJoseHeader.Algorithm);
            
            return ecdsa.SignData(SigningInput(protectedJoseHeader, JwsPayload), sha);
        }
        
        private static bool VerifyEcdsaSignature(JWK.JWK jwk, byte[] data, byte[] signature)
        {
            var ecdsa = CreateEcKeyFromJWK(jwk);
            var sha = TranslateEcHashAlgorithm(jwk.Algorithm);
            return ecdsa.VerifyData(data, signature, sha);
        }

        private static HashAlgorithmName TranslateEcHashAlgorithm(Algorithm algorithm)
        {
            HashAlgorithmName sha;
            var keyLength = algorithm.Name.Split(new string[] { "ES" }, StringSplitOptions.None)[1]; // Algorithm = 'ES' + Keylength
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
                    throw new ArgumentException("Could not create ECCurve based on algorithm: " + algorithm.Name);
            }

            return sha;
        }
        
        // Workaround: Using ECCurve.CreateFromFriendlyName results in a PlatformException for NIST curves
        private static ECCurve TranslateCurve(Algorithm algorithm)
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

        private static ECDsa CreateEcKeyFromJWK(JWK.JWK jwk)
        {
            var ecParameters = new ECParameters()
            {
                Curve = TranslateCurve(jwk.Algorithm),
            };
            
            if (jwk.KeyParameters.TryGetValue(KeyParameter.ECKeyParameterD, out var dValue))
            {
                ecParameters.D = Base64urlDecode(dValue);
            }
            
            if (jwk.KeyParameters.TryGetValue(KeyParameter.ECKeyParameterX, out var xValue) && jwk.KeyParameters.TryGetValue(KeyParameter.ECKeyParameterY, out var yValue))
            {
                ecParameters.Q = new ECPoint { X = Base64urlDecode(xValue), Y = Base64urlDecode(yValue) };
            }
            
            ecParameters.Validate();
            return ECDsa.Create(ecParameters);
        }
        
        #endregion ECDSA
        
        #region HMAC
        
        // HMAC using SHA-256 / SHA-384 / SHA-512
        private byte[] HMACSignature(ProtectedJoseHeader protectedJoseHeader)
        {
            var hmac = CreateHmacKeyFromJWK(protectedJoseHeader.JWK);
            return hmac.ComputeHash(SigningInput(protectedJoseHeader, JwsPayload));
        }
        
        private static bool VerifyHmacSignature(JWK.JWK jwk, byte[] data, byte[] signature)
        {
            var hmac = CreateHmacKeyFromJWK(jwk);
            return hmac.ComputeHash(data).SequenceEqual(signature);
        }

        private static HMAC CreateHmacKeyFromJWK(JWK.JWK jwk)
        {
            HMAC hmac;
            var key = Base64urlDecode(jwk.KeyParameters[KeyParameter.OctKeyParameterK]); // key is padded by HMACSHA* implementation to provide add least a security of 64 bytes
            switch (jwk.Algorithm.Name)
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
                    throw new CryptographicException("Could not create HMAC key based on algorithm " + jwk.Algorithm.Name + " (Could not parse expected SHA version)");
            }

            return hmac;
        }
        
        #endregion HMAC

        #region Serialization

        public string Export()
        {
            return JsonConvert.SerializeObject(this);
        }

        #endregion

    }

}
