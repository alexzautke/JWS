﻿using System;

namespace CreativeCode.JWS
{
    // See RFC 7515 JSON Web Signature - Section 3.1. JWS Compact Serialization Overview
    public sealed class SerializationOption
    {
        public static readonly SerializationOption JWSCompactSerialization = new SerializationOption("JWS Compact Serialization");
        public static readonly SerializationOption JWSJSONSerialization = new SerializationOption("JWS JSON Serialization");

        private readonly string value;

        private SerializationOption(string value)
        {
            this.value = value;
        }

        public override string ToString()
        {
            return value;
        }

    }
}