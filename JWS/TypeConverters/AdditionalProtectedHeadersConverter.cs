using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters
{
    internal class AdditionalHeadersConverter : IJWSConverter
    {
        public string Serialize(object propertyValue = null)
        {
            if (propertyValue == null)
                return string.Empty;
            
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            var writer = new JsonTextWriter(sw);
            
            var additionalHeaders = propertyValue as IReadOnlyDictionary<string, string>;
            foreach (var header in additionalHeaders!)
            {
                writer.WritePropertyName(header.Key);
                writer.WriteValue(header.Value);
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