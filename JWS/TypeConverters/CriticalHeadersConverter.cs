using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters;

public class CriticalHeadersConverter : IJWSConverter
{
    public string Serialize(object propertyValue = null)
    {
        if (propertyValue == null)
            return string.Empty;
        
        var sb = new StringBuilder();
        var sw = new StringWriter(sb);
        var writer = new JsonTextWriter(sw);
        var criticalHeaders = propertyValue as IReadOnlyList<string>;
        writer.WritePropertyName("crit");
        writer.WriteStartArray();
        foreach (var criticalHeader in criticalHeaders)
            writer.WriteValue(criticalHeader);
        writer.WriteEndArray();
        
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