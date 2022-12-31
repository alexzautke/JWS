using System;
using System.Collections.Generic;
using System.Linq;
using CreativeCode.JWS.TypeConverters;
using Newtonsoft.Json;

namespace CreativeCode.JWS
{
    [JsonConverter(typeof(JwsConverter))]
    public class JWS
    {
        // JWS parts
        [JWSConverterAttribute(typeof(ProtectedJoseHeaderConverter))]
        internal IEnumerable<ProtectedJoseHeader> ProtectedJoseHeaders { get; }
        internal byte[] JwsPayload { get; }    // Raw value, NOT base64 encoded
        internal IEnumerable<byte[]> JwsSignatures { get; }  // Raw value, NOT base64 encoded
        
        public JWS(IEnumerable<ProtectedJoseHeader> protectedJoseHeaderses, byte[] jwsPayload)
        {
            if (protectedJoseHeaderses is null)
                throw new ArgumentNullException("joseHeader MUST be provided");
            if (jwsPayload is null)
                throw new ArgumentNullException("serializationOption MUST be provided");
            if (!protectedJoseHeaderses.Any())
                throw new ArgumentException("At least one joseHeader MUST be provided");
            if (jwsPayload.Length == 0)
                throw new ArgumentException("jwsPayload MUST NOT be empty");

            ProtectedJoseHeaders = protectedJoseHeaderses;
            JwsPayload = jwsPayload;
        }

        public string Export()
        {
            return JsonConvert.SerializeObject(this);
        }
        
    }

}
