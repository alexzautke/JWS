using System;
using CreativeCode.JWS.TypeConverters;
using Newtonsoft.Json;

namespace CreativeCode.JWS
{
    [JsonConverter(typeof(JwsConverter))]
    public class JWS
    {
        // JWS parts
        [JWSConverterAttribute(typeof(ProtectedJoseHeaderConverter))]
        internal ProtectedJoseHeader ProtectedJoseHeader { get; }
        internal byte[] JwsPayload { get; }    // Raw value, NOT base64 encoded
        internal byte[] JwsSignature { get; }  // Raw value, NOT base64 encoded
        
        public JWS(ProtectedJoseHeader protectedJoseHeader, byte[] jwsPayload)
        {
            if (protectedJoseHeader is null)
                throw new ArgumentNullException("joseHeader MUST be provided");
            if (jwsPayload is null)
                throw new ArgumentNullException("serializationOption MUST be provided");
            if (jwsPayload.Length == 0)
                throw new ArgumentException("jwsPayload MUST NOT be empty");

            ProtectedJoseHeader = protectedJoseHeader;
            JwsPayload = jwsPayload;
        }

        public string Export()
        {
            return JsonConvert.SerializeObject(this);
        }
        
    }

}
