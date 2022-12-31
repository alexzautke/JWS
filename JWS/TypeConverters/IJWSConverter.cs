using System;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWS.TypeConverters
{
    internal interface IJWSConverter
    {
        string Serialize(object propertyValue = null);
        object Deserialize(JToken jwkRepresentation);
        object Deserialize(JObject jwkRepresentation);
    }

    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    internal class JWSConverterAttribute : Attribute
    {
        public Type @Type { get; }

        public JWSConverterAttribute() { }

        public JWSConverterAttribute(Type @Type)
        {
            this.Type = Type;
        }
    }
}
