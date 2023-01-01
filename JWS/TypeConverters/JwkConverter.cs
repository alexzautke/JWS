using System;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters
{
    internal class JwkConverter : IJWSConverter
    {
        public string Serialize(object propertyValue = null)
        {
            var jwk = propertyValue as JWK.JWK;
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            var writer = new JsonTextWriter(sw);
            
            if (jwk.IsSymmetric())
            {
                writer.WritePropertyName("jwk");
                writer.WriteStartObject();
                writer.WriteEndObject();
            }
            else
            {
                writer.WritePropertyName("jwk");
                writer.WriteRaw(jwk.Export());   
            }

            return sb.ToString();
        }

        public object Deserialize(JToken jwkRepresentation)
        {
            throw new System.NotImplementedException();
        }

        public object Deserialize(JObject jwkRepresentation)
        {
            throw new System.NotImplementedException();
        }
    }
}