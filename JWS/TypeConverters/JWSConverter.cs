using System;
using System.Linq;
using System.Reflection;
using System.Text;
using Newtonsoft.Json;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWS.TypeConverters
{
    internal class JWSConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (!(value is JWS))
                throw new ArgumentException("JWS Converter can only objects serialize the type 'JWS'. Found object of type " + value.GetType() + " instead.");

            var jws = (JWS) value;
            
            // 1.  Create the content to be used as the JWS Payload.
            // 2.  Compute the encoded payload value BASE64URL(JWS Payload).

            var urlEncodedPayload = Base64urlEncode(jws.JwsPayload);
            
            /*
             
                3.  Create the JSON object(s) containing the desired set of Header
                Parameters, which together comprise the JOSE Header (the JWS
                Protected Header and/or the JWS Unprotected Header).
                
             */

            var type = value.GetType();
            var joseHeaderProperty = type.GetProperty("ProtectedJoseHeader", BindingFlags.NonPublic|BindingFlags.Instance);
            var customConverterAttribute = joseHeaderProperty.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(JWSConverterAttribute));
            var customConverterType = customConverterAttribute.ConstructorArguments.FirstOrDefault(a => a.ArgumentType == typeof(Type)).Value;
            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWSConverter;
            var protectedJoseHeaderJson = instance.Serialize(joseHeaderProperty.GetValue(value));

            /*
             
             4.  Compute the encoded header value BASE64URL(UTF8(JWS Protected
             Header)).  If the JWS Protected Header is not present (which can
             only happen when using the JWS JSON Serialization and no
             "protected" member is present), let this value be the empty
             string.
             
             */
            
            if(jws.ProtectedJoseHeader.Type == SerializationOption.JwsCompactSerialization && protectedJoseHeaderJson.Length == 0)
                throw new InvalidOperationException("When using the compact serialization, there MUST be a JWS Protected Header.");
            
            var urlEncodedProtectedHeader = Base64urlEncode(Encoding.UTF8.GetBytes(protectedJoseHeaderJson));
            
            /*
             
             5.  Compute the JWS Signature in the manner defined for the
             particular algorithm being used over the JWS Signing Input
             ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
             BASE64URL(JWS Payload)).  The "alg" (algorithm) Header Parameter
             MUST be present in the JOSE Header, with the algorithm value
             accurately representing the algorithm used to construct the JWS
             Signature.
             
             6.  Compute the encoded signature value BASE64URL(JWS Signature).
             
             7.  If the JWS JSON Serialization is being used, repeat this process
             (steps 3-6) for each digital signature or MAC operation being
             performed.
             
             Note: the signature generation is performed independently of the JWS serialization 
             
             */

            var urlEncodedSignature = Base64urlEncode(jws.JwsSignature);
            
            /*
            
            8.  Create the desired serialized output.  The JWS Compact
            Serialization of this result is BASE64URL(UTF8(JWS Protected
            Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS
            Signature).  The JWS JSON Serialization is described in
            Section 7.2.
            
            */

            if (jws.ProtectedJoseHeader.Type == SerializationOption.JwsCompactSerialization)
                CompactSerialization(writer, urlEncodedProtectedHeader, urlEncodedPayload, urlEncodedSignature);
            if (jws.ProtectedJoseHeader.Type == SerializationOption.JwsFlattenedJsonSerialization || jws.ProtectedJoseHeader.Type == SerializationOption.JwsCompleteJsonSerialization)
                JSONSerialization(writer, jws);
        }

        private void CompactSerialization(JsonWriter writer, string urlEncodedProtectedHeader, string urlEncodedPayload, string urlEncodedSignature)
        {
            writer.WriteRaw($"{urlEncodedProtectedHeader}.{urlEncodedPayload}.{urlEncodedSignature}");
        }
        
        private void JSONSerialization(JsonWriter writer, JWS jws)
        {
            throw new NotImplementedException();
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(JWS);
        }
    }
}