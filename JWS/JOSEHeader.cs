using System;
using Newtonsoft.Json;

namespace CreativeCode.JWS
{

    /*
     
     See RFC7517 JSON Web Signature - Section 3. JSON Web Signature (JWS) Overview       
     
     For a JWS, the JOSE Header members are the union of the members of
     these values:
       o  JWS Protected Header
       o  JWS Unprotected Header
             
     In the JWS Compact Serialization, no JWS Unprotected Header is used.

    In the JWS JSON Serialization, one or both of the JWS Protected
    Header and JWS Unprotected Header MUST be present.  In this case, the
    members of the JOSE Header are the union of the members of the JWS
    Protected Header and the JWS Unprotected Header values that are
    present.       
             
    */

    public class JOSEHeader
    {
        [JsonProperty(PropertyName = "alg")]
        public string Algorithm { get; internal set; }      // REQUIRED, must match the 'alg' value of the supplied JWK

        [JsonProperty(PropertyName = "jwk")]
        public string JWK { get; internal set; }            // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        public string KeyID { get; internal set; }          // OPTIONAL

        [JsonProperty(PropertyName = "typ")]
        public string Type { get; internal set; }           // OPTIONAL

        [JsonProperty(PropertyName = "cty")]
        public string ContentType { get; internal set; }    // OPTIONAL

        public JOSEHeader(IJWKProvider jwkProvider, string contentType)
        {
            Algorithm = jwkProvider.Algorithm();
            JWK = jwkProvider.PublicJWK();
            KeyID = jwkProvider.KeyId();
            ContentType = contentType;
        }
    }
}
