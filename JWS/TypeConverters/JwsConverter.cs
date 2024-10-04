using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Newtonsoft.Json;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWS.TypeConverters
{
    internal class JwsConverter : JsonConverter
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
            var joseHeadersProperty = type.GetProperty("ProtectedJoseHeaders", BindingFlags.NonPublic|BindingFlags.Instance);
            var customConverterAttribute = joseHeadersProperty.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(JWSConverterAttribute));
            var customConverterType = customConverterAttribute.ConstructorArguments.FirstOrDefault(a => a.ArgumentType == typeof(Type)).Value;
            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWSConverter;
            var joseHeaders = (joseHeadersProperty.GetValue(value) as IEnumerable<ProtectedJoseHeader>).ToList();

            if (joseHeaders.Any(joseHeader => joseHeader.Type == SerializationOption.JwsCompactSerialization || joseHeader.Type == SerializationOption.JwsFlattenedJsonSerialization) && joseHeaders.Count() > 1)
                throw new InvalidOperationException("Multiple headers/signatures are only supported using the General JWS JSON Serialization Syntax. At least one header specified a JWS Compact Serialization or Flattened JWS JSON Serialization Syntax.");
            
            var protectedJoseHeadersJson = joseHeaders.Select(joseHeader => instance.Serialize(joseHeader));   
            
            /*
             
             4.  Compute the encoded header value BASE64URL(UTF8(JWS Protected
             Header)).  If the JWS Protected Header is not present (which can
             only happen when using the JWS JSON Serialization and no
             "protected" member is present), let this value be the empty
             string.
             
             */
            
            var urlEncodedProtectedHeaders = protectedJoseHeadersJson.Select(protectedJoseHeaderJson => Base64urlEncode(Encoding.UTF8.GetBytes(protectedJoseHeaderJson)));
            
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

            if (jws.JwsSignatures is null || !jws.JwsSignatures.Any())
                throw new InvalidOperationException("The JWS signature(s) MUST be calculated be before serialization.");
            
            var urlEncodedSignatures = jws.JwsSignatures.Select(Base64urlEncode);
            
            /*
            
            8.  Create the desired serialized output.  The JWS Compact
            Serialization of this result is BASE64URL(UTF8(JWS Protected
            Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS
            Signature).  The JWS JSON Serialization is described in
            Section 7.2.
            
            */

            if (jws.ProtectedJoseHeaders.All(protectedJoseHeader => protectedJoseHeader.Type == SerializationOption.JwsCompactSerialization))
                CompactSerialization(writer, urlEncodedProtectedHeaders.First(), urlEncodedPayload, urlEncodedSignatures.First(), jws.ContentMode);
            else if (jws.ProtectedJoseHeaders.All(protectedJoseHeader => protectedJoseHeader.Type == SerializationOption.JwsFlattenedJsonSerialization))
                FlattenedJsonSerialization(writer, urlEncodedPayload, urlEncodedProtectedHeaders.First(), urlEncodedSignatures.First(), jws.ContentMode);
            else if (jws.ProtectedJoseHeaders.All(protectedJoseHeader => protectedJoseHeader.Type == SerializationOption.JwsCompleteJsonSerialization))
                CompleteJsonSerialization(writer, urlEncodedPayload, urlEncodedProtectedHeaders, urlEncodedSignatures, jws.ContentMode);
            else
                throw new InvalidOperationException("JWS Protected headers indicated mixed serialization options. All headers MUST use the same option.");
        }

        private void CompactSerialization(JsonWriter writer, string urlEncodedProtectedHeader, string urlEncodedPayload, string urlEncodedSignature, ContentMode contentMode)
        {
            if(contentMode == ContentMode.Complete)
                writer.WriteRaw($"{urlEncodedProtectedHeader}.{urlEncodedPayload}.{urlEncodedSignature}");
            else
                writer.WriteRaw($"{urlEncodedProtectedHeader}..{urlEncodedSignature}");
        }
        
        private void FlattenedJsonSerialization(JsonWriter writer, string urlEncodedPayload, string urlEncodedProtectedHeader, string urlEncodedSignature, ContentMode contentMode)
        {
            writer.WriteStartObject();
            
            if (contentMode == ContentMode.Complete)
            {
                writer.WritePropertyName("payload");
                writer.WriteValue(urlEncodedPayload);   
            }
            
            writer.WritePropertyName("protected");
            writer.WriteValue(urlEncodedProtectedHeader);
            
            writer.WritePropertyName("signature");
            writer.WriteValue(urlEncodedSignature);
            
            writer.WriteEndObject();
        }
        
        private void CompleteJsonSerialization(JsonWriter writer, string urlEncodedPayload, IEnumerable<string> urlEncodedProtectedHeaders, IEnumerable<string> urlEncodedSignatures, ContentMode contentMode)
        {
            if (urlEncodedProtectedHeaders.Count() != urlEncodedSignatures.Count())
                throw new InvalidOperationException("Count of protected JoseHeaders does not match count of provided signatures.");
            
            writer.WriteStartObject();

            if (contentMode == ContentMode.Complete)
            {
                writer.WritePropertyName("payload");
                writer.WriteValue(urlEncodedPayload);   
            }
            
            writer.WritePropertyName("signatures");
            writer.WriteStartArray();

            for (int i = 0; i < urlEncodedSignatures.Count(); i++)
            {
                writer.WriteStartObject();
                
                writer.WritePropertyName("protected");
                writer.WriteValue(urlEncodedProtectedHeaders.ElementAt(i));
            
                writer.WritePropertyName("signature");
                writer.WriteValue(urlEncodedSignatures.ElementAt(i));
                
                writer.WriteEndObject();
            }
            
            writer.WriteEndArray();
            writer.WriteEndObject();
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