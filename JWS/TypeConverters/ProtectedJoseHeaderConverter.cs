using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters
{
    internal class ProtectedJoseHeaderConverter : IJWSConverter
    {
        private JsonWriter _writer;
        
        public string Serialize(object value = null)
        {
            if (!(value is ProtectedJoseHeader))
                throw new ArgumentException("JoseHeader Converter can only objects serialize the type 'JoseHeader'. Found object of type " + value.GetType() + " instead.");
            
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            _writer = new JsonTextWriter(sw);
            
            _writer.WriteStartObject();

            var type = value.GetType();
            var properties = type.GetProperties(); // Get all public properties
            var head = properties.First();
            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(value);
                if (propertyValue is null)
                    continue;
                
                foreach (var customAttribute in property.CustomAttributes){
                
                    if (customAttribute.AttributeType != typeof(JsonPropertyAttribute))
                        break; // Only serialize fields which are marked with "JsonProperty"

                    var customJSONPropertyName = customAttribute.NamedArguments.ElementAtOrDefault(0).TypedValue.ToString();
                    WriteTrailingComma(head, property);

                    var customConverterAttribute = property.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(JWSConverterAttribute));
                    if (customConverterAttribute is { }) // Let the type handle the serialization itself as there is a custom serialization needed
                    {
                        var customConverterType = customConverterAttribute.ConstructorArguments.FirstOrDefault(a => a.ArgumentType == typeof(Type)).Value;
                        if(customConverterType is { })
                        {
                            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWSConverter;
                            _writer.WriteRaw(instance.Serialize(propertyValue));
                        }
                    }
                    else if (propertyValue is IJWSConverter)
                        _writer.WriteRaw(customJSONPropertyName + ":\"" + ((IJWSConverter)propertyValue).Serialize() + "\"");

                    else // Serialize system types directly
                        _writer.WriteRaw(customJSONPropertyName + ":\"" + propertyValue + "\"");
                }
            }
            
            _writer.WriteEndObject();

            return sb.ToString();
        }
        
        private void WriteTrailingComma(PropertyInfo head, PropertyInfo property)
        {
            if (property != head) // Don't start the JSON object with a comma
            {
                _writer.WriteRaw(",");
            }
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