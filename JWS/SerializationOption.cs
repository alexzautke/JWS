using System;

namespace CreativeCode.JWS
{
    // See RFC 7515 JSON Web Signature - Section 3.1. JWS Compact Serialization Overview
    public sealed class SerializationOption
    {
        public static readonly SerializationOption JwsCompactSerialization = new SerializationOption("JOSE");
        public static readonly SerializationOption JwsFlattenedJsonSerialization = new SerializationOption("JOSE+JSON");
        public static readonly SerializationOption JwsCompleteJsonSerialization = new SerializationOption("JOSE+JSON");

        public readonly string Name;

        private SerializationOption(string name)
        {
            Name = name;
        }
        
    }
}
