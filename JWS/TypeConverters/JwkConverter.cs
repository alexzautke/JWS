using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters
{
    public class JwkConverter : IJWSConverter
    {
        public string Serialize(object propertyValue = null)
        {
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            var writer = new JsonTextWriter(sw);
            writer.WritePropertyName("jwk");
            writer.WriteRaw((propertyValue as JWK.JWK).Export());

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