using System.IO;
using System.Text;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters
{
    internal class AlgorithmConverter : IJWSConverter
    {
        public string Serialize(object propertyValue = null)
        {
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            var writer = new JsonTextWriter(sw);
            writer.WritePropertyName("alg");
            writer.WriteValue((propertyValue as Algorithm).Name);

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