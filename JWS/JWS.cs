using System;
using System.Text;
using Newtonsoft.Json;

namespace CreativeCode.JWS
{
    public class JWS
    {
        private JOSEHeader _joseHeader;
        private byte[] _jwsPayload;
        private byte[] _jwsSignature;

        private IJWKProvider _jwkProvider;

        public JWS(IJWKProvider jwkProvider)
        {
            CheckNotNull(jwkProvider, nameof(jwkProvider));
            _jwkProvider = jwkProvider;
        }

        public string SerializeJWSWithOptions(JOSEHeader joseHeader, byte[] jwsPayload, SerializationOption serializationOption)
        {
            _joseHeader = joseHeader;
            _jwsPayload = jwsPayload;

            var keyType = _jwkProvider.KeyType();
            switch (keyType)
            {
                case "EC":
                    _jwsSignature = Oct_Signature();
                    break;
                case "RSA":
                    _jwsSignature = RSASSA_PKCS1_v1_5_Signature();
                    break;
                case "oct":
                    _jwsSignature = HMACSignature();
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
        public byte[] HMACSignature()
        {
            throw new NotImplementedException("HMAC signatures are not yet supported!");
        }

        // RSASSA-PKCS1-v1_5 using SHA-256 / SHA-384 / SHA-512
        public byte[] RSASSA_PKCS1_v1_5_Signature()
        {
            throw new NotImplementedException("RSASSA-PKCS1-v1_5 signatures are not yet supported!");
        }

        // ECDSA using (P-256 / P-384 / P-521) and SHA-256 / SHA-384 / SHA-512
        // None
        public byte[] Oct_Signature()
        {
            throw new NotImplementedException("ECDSA / None signatures are not yet supported!");
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
