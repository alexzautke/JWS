using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using CreativeCode.JWK.KeyParts;
using CreativeCode.JWS.TypeConverters;
using Newtonsoft.Json;

namespace CreativeCode.JWS
{

    /*

     See RFC7515 JSON Web Signature - Section 3. JSON Web Signature (JWS) Overview       
     
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

    public class ProtectedJoseHeader
    {
        private static IReadOnlyList<string> _jsonPropertyNamesDefinedByJws = new[]
            {"alg", "jwk", "kid", "typ", "cty", "crit", "x5t#S256", "x5t", "x5c", "x5u", "jku"};
            
        [JsonProperty(PropertyName = "alg")]
        [JWSConverterAttribute(typeof(AlgorithmConverter))]
        public Algorithm Algorithm { get; internal set; }      // REQUIRED, must match the 'alg' value of the supplied JWK

        [JsonProperty(PropertyName = "jwk")]
        [JWSConverterAttribute(typeof(JwkConverter))]
        public JWK.JWK JWK { get; internal set; }           // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        public string KeyID { get; internal set; }          // OPTIONAL

        [JsonProperty(PropertyName = "typ")]
        [JWSConverterAttribute(typeof(SerializationOptionConverter))]
        public SerializationOption Type { get; internal set; }           // OPTIONAL
        
        [JsonProperty(PropertyName = "cty")]
        public string ContentType { get; internal set; }    // OPTIONAL
        
        [JsonProperty()]
        [JWSConverterAttribute(typeof(AdditionalHeadersConverter))]
        public IReadOnlyDictionary<string, object> AdditionalHeaders { get; internal set; } // OPTIONAL
        
        [JsonProperty("crit")]
        [JWSConverterAttribute(typeof(CriticalHeadersConverter))]
        public IReadOnlyList<string> CriticalHeaders { get; internal set; } // OPTIONAL

        public ProtectedJoseHeader(JWK.JWK jwk, string contentType, SerializationOption serializationOption)
        {
            if (jwk is null)
                throw new ArgumentNullException("jwk MUST be provided");
            
            if (string.IsNullOrEmpty(contentType))
                throw new ArgumentNullException("contentType MUST be provided and MUST NOT be empty");
            
            JWK = jwk;
            Algorithm = jwk.Algorithm;
            KeyID = jwk.KeyID;
            Type = serializationOption;
            ContentType = ShortenContentType(contentType);
        }

        public ProtectedJoseHeader(JWK.JWK jwk, SerializationOption serializationOption, string contentType = null,
            IReadOnlyDictionary<string, object> additionalHeaders = null,
            IReadOnlyList<string> criticalHeaders = null)
        {
            if (jwk is null)
                throw new ArgumentNullException("jwk MUST be provided");
            
            JWK = jwk;
            Algorithm = jwk.Algorithm;
            KeyID = jwk.KeyID;
            Type = serializationOption;
            ContentType = ShortenContentType(contentType);
            AdditionalHeaders = additionalHeaders;

            CheckCriticalHeaders(criticalHeaders, additionalHeaders);
            CriticalHeaders = criticalHeaders;
        }
        
        /*
           Producers
           MUST NOT include Header Parameter names defined by this specification
           or [JWA] for use with JWS, duplicate names, or names that do not
           occur as Header Parameter names within the JOSE Header in the "crit"
           list.
           
            See RFC7515 - Section 4.1.11.  "crit" (Critical) Header Parameter
         */

        private void CheckCriticalHeaders(IReadOnlyList<string> criticalHeaders, IReadOnlyDictionary<string, object> additionalHeaders)
        {
            if (criticalHeaders is null)
                return;
            
            if (criticalHeaders.Count != criticalHeaders.Distinct().Count())
                throw new ArgumentException("Values provided to be used within the 'crit' header MUST be unique");
            
            if(_jsonPropertyNamesDefinedByJws.Intersect(criticalHeaders).Any())
                throw new ArgumentException("Values provided to be used within the 'crit' header MUST not overlap with any header name defined in RFC7515");

            if (additionalHeaders is null || !criticalHeaders.All(additionalHeaders.ContainsKey))
                throw new ArgumentException("Values provided to be used within the 'crit' header MUST also be listed as additional headers");
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
