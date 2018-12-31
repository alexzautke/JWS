using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS
{
    public class JWS
    {
        // JWS parts
        private JOSEHeader _joseHeader;
        private byte[] _jwsPayload;     // Raw value, NOT base64 encoded
        private byte[] _jwsSignature;   // Raw value, NOT base64 encoded

        // Internal
        private IJWKProvider _jwkProvider;

        public JWS(IJWKProvider jwkProvider)
        {
            CheckNotNull(jwkProvider, nameof(jwkProvider));
            _jwkProvider = jwkProvider;
        }

        public string SerializeJWSWithOptions(JOSEHeader joseHeader, byte[] jwsPayload, SerializationOption serializationOption)
        {
            CheckNotNull(joseHeader, nameof(joseHeader));
            CheckNotNull(jwsPayload, nameof(jwsPayload));
            CheckNotNull(serializationOption, nameof(serializationOption));

            _joseHeader = joseHeader;
            _jwsPayload = jwsPayload;

            var keyType = _jwkProvider.KeyType();
            var key = _jwkProvider.PrivateJWK();
            switch (keyType)
            {
                case "EC":
                    _jwsSignature = ECDSA_Signature(key);
                    break;
                case "RSA":
                    _jwsSignature = RSASSA_PKCS1_v1_5_Signature();
                    break;
                case "oct":
                    _jwsSignature = HMACSignature(key);
                    break;
                default:
                    throw new ArgumentException("Can not create a signature with key with KeyType: " + keyType);
            }

            if (serializationOption == SerializationOption.JWSCompactSerialization)
            {
                joseHeader.Type = "JOSE";
                return CompactSerialization();
            }
            else
            {
                joseHeader.Type = "JOSE+JSON";
                return JSONSerialization();
            }
        }

        #region Signature

        // HMAC using SHA-256 / SHA-384 / SHA-512
        public byte[] HMACSignature(string symetricKey)
        {
            JObject parsedPrivateKeyJSON = JObject.Parse(symetricKey);
            var key = Base64urlDecode(KeyParameter("k", parsedPrivateKeyJSON)); // key is padded by HMACSHA* implementation to provide add least a security of 64 bytes
            var alg = KeyParameter("alg", parsedPrivateKeyJSON);

            HMAC hmac;
            switch (alg)
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
                    throw new CryptographicException("Could not create HMAC key based on algorithm " + alg + " (Could not parse expected SHA version)");
            }

            return hmac.ComputeHash(SigningInput());
        }

        // RSASSA-PKCS1-v1_5 using SHA-256 / SHA-384 / SHA-512
        public byte[] RSASSA_PKCS1_v1_5_Signature()
        {
            throw new NotImplementedException("RSASSA-PKCS1-v1_5 signatures are not yet supported!");
        }

        // ECDSA using (P-256 / P-384 / P-521) and SHA-256 / SHA-384 / SHA-512
        public byte[] ECDSA_Signature(string privateKey)
        {
            JObject parsedPrivateKeyJSON = JObject.Parse(privateKey);
            var ecParameters = new ECParameters();
            ecParameters.Q.X = Base64urlDecode(KeyParameter("x", parsedPrivateKeyJSON));
            ecParameters.Q.Y = Base64urlDecode(KeyParameter("y", parsedPrivateKeyJSON));
            ecParameters.D = Base64urlDecode(KeyParameter("d", parsedPrivateKeyJSON));

            HashAlgorithmName sha;
            var algorithm = KeyParameter("alg", parsedPrivateKeyJSON);
            var keyLength = algorithm.Split("ES")[1]; // Algorithm = 'ES' + Keylength
            var curveName = "P-" + keyLength;
            Oid curveOid = null; // Workaround: Using ECCurve.CreateFromFriendlyName results in a PlatformException for NIST curves
            switch (keyLength)
            {
                case "256":
                    sha = HashAlgorithmName.SHA256;
                    curveOid = new Oid("1.2.840.10045.3.1.7");
                    break;
                case "384":
                    sha = HashAlgorithmName.SHA384;
                    curveOid = new Oid("1.3.132.0.34");
                    break;
                case "512":
                    sha = HashAlgorithmName.SHA512;
                    curveOid = new Oid("1.3.132.0.35");
                    break;
                default:
                    throw new ArgumentException("Could not create ECCurve based on algorithm: " + algorithm);
            }
            var curve = ECCurve.CreateFromOid(curveOid);
            ecParameters.Curve = curve;
            ecParameters.Validate();

            var ecdsa = ECDsa.Create(ecParameters);
            return ecdsa.SignData(SigningInput(), sha);
        }

        #endregion Signature

        #region Serialization

        private string CompactSerialization()
        {
            var base64JOSEHeader = Base64urlEncode(UTF8(_joseHeader.ToString()));
            var base64JWSPayload = Base64urlEncode(_jwsPayload);
            var base64JWSSignature = Base64urlEncode(_jwsSignature);
            return base64JOSEHeader + "." + base64JWSPayload + "." + base64JWSSignature;
        }

        private string JSONSerialization()
        {
            throw new NotImplementedException("JWS JSON Serialization is not yet supported!");
        }

        #endregion Serialization

        #region Crypto helper methods

        public string KeyParameter(string index, JObject key)
        {
            var value = key[index];
            if (value == null)
                throw new CryptographicException("Invalid key provided for algorithm: " + _jwkProvider.Algorithm() + ". Missing key parameter: " + index);

            return value.ToString();
        }

        public byte[] SigningInput()
        {
            return ASCII(Base64urlEncode(UTF8(_joseHeader.ToString())) + "." + Base64urlEncode(_jwsPayload));
        }

        #endregion Crypto helper methods

        #region Helper methods

        private byte[] ASCII(string s)
        {
            return Encoding.ASCII.GetBytes(s);
        }

        private byte[] UTF8(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        private string Base64urlEncode(byte[] s)
        {
            string base64 = Convert.ToBase64String(s); // Regular base64 encoder
            base64 = base64.Split('=')[0]; // Remove any trailing '='s
            base64 = base64.Replace('+', '-');
            base64 = base64.Replace('/', '_');
            return base64;
        }

        private byte[] Base64urlDecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: 
                    break; // No pad chars in this case
                case 2: 
                    s += "=="; break; // Two pad chars
                case 3: 
                    s += "="; break; // One pad char
                default: 
                    throw new System.Exception("Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        private void CheckNotNull(object toCheck, string argumentName)
        {
            if (toCheck == null)
                throw new ArgumentException(argumentName + " must not be null!");
        }

        # endregion Helper methods
    }

}
