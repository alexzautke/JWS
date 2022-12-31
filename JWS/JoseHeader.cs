using System;
using System.Linq;
using System.Text.RegularExpressions;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;
using static CreativeCode.JWS.SerializationOption;

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

    public class JoseHeader
    {
        [JsonProperty(PropertyName = "alg")]
        public Algorithm Algorithm { get; internal set; }      // REQUIRED, must match the 'alg' value of the supplied JWK

        [JsonProperty(PropertyName = "jwk")]
        public JWK.JWK JWK { get; internal set; }           // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        public string KeyID { get; internal set; }          // OPTIONAL

        [JsonProperty(PropertyName = "typ")]
        public string Type { get; internal set; }           // OPTIONAL

        [JsonProperty(PropertyName = "cty")]
        public string ContentType { get; internal set; }    // OPTIONAL

        public JoseHeader(JWK.JWK jwk, string contentType, SerializationOption serializationOption)
        {
            if (jwk is null)
                throw new ArgumentNullException("jwk MUST be provided");
            
            Algorithm = jwk.Algorithm;
            KeyID = jwk.KeyID;
            Type = JWSCompactSerialization.Name;
            ContentType = ShortenContentType(contentType);
        }

        /*
        To keep messages compact in common situations, it is RECOMMENDED that
        producers omit an "application/" prefix of a media type value in a
        "cty" Header Parameter when no other '/' appears in the media type
        value.

        See RFC7515 - Section 4.1.10.  "cty" (Content Type) Header Parameter

        */
        private string ShortenContentType(string contentType)
        {
            Regex shortContentTypeSplit = new Regex(@"(?<backslash>/+)", RegexOptions.Compiled);
            if (shortContentTypeSplit.Match(contentType).Captures.Count > 1)
                return contentType;

            return shortContentTypeSplit.Split(contentType).Last(); // Split : ["application", "/", "contentTyp"]
        }
    }
}
