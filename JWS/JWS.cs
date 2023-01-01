using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
            JwsSignatures = new[] {Encoding.UTF8.GetBytes("Test")};
        }

        public string Export()
        {
            return JsonConvert.SerializeObject(this);
        }
        
    }

}
