using System.Text;
using System.Text.RegularExpressions;
using CreativeCode.JWK.KeyParts;
using Xunit;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using static CreativeCode.JWK.Base64Helper;
using static CreativeCode.JWS.JWS;

namespace CreativeCode.JWS.Tests;

public class JwsTests
{
    
    [Fact]
    public void CompactJwsWithRsaSignatureCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.RS256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var joseHeader = new ProtectedJoseHeader(jwk, "application/fhir+json", SerializationOption.JwsCompactSerialization);
        var payload = Encoding.UTF8.GetBytes("payload");

        var jws = new JWS(new []{joseHeader}, payload);
        jws.CalculateSignature();
        var jwsCompactJson = jws.Export();

        var parts = jwsCompactJson.Split(".");
        parts.Count().Should().Be(3, "A JWS using compact serialization should consist of three parts");

        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(parts.First()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);

        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("RS256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(7);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("n").ToString().Should().Be(jwk.KeyParameters[KeyParameter.RSAKeyParameterN]);
        parsedJwk.GetValue("e").ToString().Should().Be(jwk.KeyParameters[KeyParameter.RSAKeyParameterE]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("fhir+json");
        
        var payloadFromJws = Encoding.UTF8.GetString(Base64urlDecode(parts.ElementAt(1)));
        payloadFromJws.Length.Should().BePositive("A JWS payload should be present");
        payloadFromJws.Should().Be("payload");
        
        var signature = parts.Last();
        signature.Length.Should().BePositive("A JWS signature should be present");

        var publicKey = new JWK.JWK(jwk.Export());
        VerifySignature(publicKey, SigningInput(joseHeader, Encoding.UTF8.GetBytes("payload")), Base64urlDecode(signature)).Should().BeTrue();
    }
    
    [Fact]
    public void CompactJwsWithEcSignatureCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.ES256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var joseHeader = new ProtectedJoseHeader(jwk, "application/fhir+json", SerializationOption.JwsCompactSerialization);
        var payload = Encoding.UTF8.GetBytes("payload");

        var jws = new JWS(new []{joseHeader}, payload);
        jws.CalculateSignature();
        var jwsCompactJson = jws.Export();

        var parts = jwsCompactJson.Split(".");
        parts.Count().Should().Be(3, "A JWS using compact serialization should consist of three parts");

        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(parts.First()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);

        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("ES256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(8);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("crv").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterCRV]);
        parsedJwk.GetValue("y").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterY]);
        parsedJwk.GetValue("x").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterX]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("fhir+json");
        
        var payloadFromJws = Encoding.UTF8.GetString(Base64urlDecode(parts.ElementAt(1)));
        payloadFromJws.Length.Should().BePositive("A JWS payload should be present");
        payloadFromJws.Should().Be("payload");
        
        var signature = parts.Last();
        signature.Length.Should().BePositive("A JWS signature should be present");

        var publicKey = new JWK.JWK(jwk.Export());
        VerifySignature(publicKey, SigningInput(joseHeader, Encoding.UTF8.GetBytes("payload")), Base64urlDecode(signature)).Should().BeTrue();
    }
    
    [Fact]
    public void CompactJwsWithOctSignatureCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.HS256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var joseHeader = new ProtectedJoseHeader(jwk, "application/fhir+json", SerializationOption.JwsCompactSerialization);
        var payload = Encoding.UTF8.GetBytes("payload");

        var jws = new JWS(new []{joseHeader}, payload);
        jws.CalculateSignature();
        var jwsCompactJson = jws.Export();

        var parts = jwsCompactJson.Split(".");
        parts.Count().Should().Be(3, "A JWS using compact serialization should consist of three parts");

        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(parts.First()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);

        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(0);
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("HS256");
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("fhir+json");
        
        var payloadFromJws = Encoding.UTF8.GetString(Base64urlDecode(parts.ElementAt(1)));
        payloadFromJws.Length.Should().BePositive("A JWS payload should be present");
        payloadFromJws.Should().Be("payload");
        
        var signature = parts.Last();
        signature.Length.Should().BePositive("A JWS signature should be present");
        
        VerifySignature(jwk, SigningInput(joseHeader, Encoding.UTF8.GetBytes("payload")), Base64urlDecode(signature)).Should().BeTrue();
    }

    [Fact]
    public void FlattenedJwsWithRsaSignatureCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.RS256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var joseHeader = new ProtectedJoseHeader(jwk, "application/fhir+json", SerializationOption.JwsFlattenedJsonSerialization);
        var payload = Encoding.UTF8.GetBytes("payload");

        var jws = new JWS(new []{joseHeader}, payload);
        jws.CalculateSignature();
        var jwsFlattenedJson = jws.Export();
        var parsedJwsFlattenedJson = JObject.Parse(jwsFlattenedJson);
        
        var payloadFromJws = Encoding.UTF8.GetString(Base64urlDecode(parsedJwsFlattenedJson.GetValue("payload").ToString()));
        payloadFromJws.Length.Should().BePositive("A JWS payload should be present");
        payloadFromJws.Should().Be("payload");
        
        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(parsedJwsFlattenedJson.GetValue("protected").ToString()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);
        
        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("RS256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(7);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("n").ToString().Should().Be(jwk.KeyParameters[KeyParameter.RSAKeyParameterN]);
        parsedJwk.GetValue("e").ToString().Should().Be(jwk.KeyParameters[KeyParameter.RSAKeyParameterE]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE+JSON");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("fhir+json");
        
        var signature = Encoding.UTF8.GetString(Base64urlDecode(parsedJwsFlattenedJson.GetValue("signature").ToString()));
        signature.Length.Should().BePositive("A JWS signature should be present");
    }
    
    [Fact]
    public void CompleteJwsWithRsaSignatureCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.RS256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var joseHeader = new ProtectedJoseHeader(jwk, "application/fhir+json", SerializationOption.JwsCompleteJsonSerialization);
        var payload = Encoding.UTF8.GetBytes("payload");

        var jws = new JWS(new []{joseHeader}, payload);
        jws.CalculateSignature();
        var jwsCompleteJson = jws.Export();
        var parsedJwsCompleteJson = JObject.Parse(jwsCompleteJson);
        
        var payloadFromJws = Encoding.UTF8.GetString(Base64urlDecode(parsedJwsCompleteJson.GetValue("payload").ToString()));
        payloadFromJws.Length.Should().BePositive("A JWS payload should be present");
        payloadFromJws.Should().Be("payload");
        
        var signatures = (JObject)parsedJwsCompleteJson.GetValue("signatures").First;
        
        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(signatures.GetValue("protected").ToString()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);
        
        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("RS256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(7);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("n").ToString().Should().Be(jwk.KeyParameters[KeyParameter.RSAKeyParameterN]);
        parsedJwk.GetValue("e").ToString().Should().Be(jwk.KeyParameters[KeyParameter.RSAKeyParameterE]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE+JSON");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("fhir+json");
        
        var signature = Encoding.UTF8.GetString(Base64urlDecode(signatures.GetValue("signature").ToString()));
        signature.Length.Should().BePositive("A JWS signature should be present");
    }

    [Fact]
    public async Task JWSCanBeSerializedInParallel()
    {
        void export()
        {
            var joseHeader = new ProtectedJoseHeader(
                new JWK.JWK(
                    Algorithm.RS256, 
                    PublicKeyUse.Signature, 
                    new HashSet<KeyOperation>(new[]
                    {
                        KeyOperation.ComputeDigitalSignature, 
                        KeyOperation.VerifyDigitalSignature
                    })
                ), 
                "application/fhir+json", 
                SerializationOption.JwsCompactSerialization
            );
            
            var payload = Encoding.UTF8.GetBytes("payload");

            var jws = new JWS(new []{joseHeader}, payload);
            jws.CalculateSignature();
            jws.Export();
        }
        
        var tasks = Enumerable.Range(0, 4).Select(_ => Task.Run(export));
        await Task.WhenAll(tasks);
    }

    [Fact]
    public void JwsWithAdditionalProtectedHeadersAndDetachedModeCanBeSerializedWithCompactSerialization()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.ES256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var payloadJson = @"{
            ""key1"": ""test"",
            ""key2"": ""test2"",
            ""testArray"": [
                {
                    ""complexTest"": ""test"",
                    ""success"": true
                }
            ]
        }";
        var payloadJsonNormalized = Regex.Replace(payloadJson, @"\s+", string.Empty, RegexOptions.Compiled);
        var payload = Encoding.UTF8.GetBytes(payloadJsonNormalized);
        var additionalHeaders = new Dictionary<string, string>()
        {
            {"testKey", "testValue"},
            {"testKey2", "testValue2"},
        };
        
        var joseHeader = new ProtectedJoseHeader(jwk, SerializationOption.JwsCompactSerialization, "application/json", additionalHeaders);
        var jws = new JWS(new []{joseHeader}, payload, ContentMode.Detached);
        jws.CalculateSignature();
        var jwsCompactJson = jws.Export();
        
        var parts = jwsCompactJson.Split(".");
        parts.Count().Should().Be(3, "A JWS using compact serialization should consist of three parts");
        
        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(parts.First()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);
        
        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("testKey", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("testKey2", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("ES256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(8);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("crv").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterCRV]);
        parsedJwk.GetValue("y").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterY]);
        parsedJwk.GetValue("x").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterX]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("json");
        parsedProtectedHeader.GetValue("testKey").ToString().Should().Be("testValue");
        parsedProtectedHeader.GetValue("testKey2").ToString().Should().Be("testValue2");

        var payloadFromJws = parts.ElementAt(1);
        payloadFromJws.Length.Should().Be(0, "Payload should be empty due to detached content mode");
        
        var signature = parts.Last();
        signature.Length.Should().BePositive("A JWS signature should be present");

        var publicKey = new JWK.JWK(jwk.Export());
        VerifySignature(publicKey, SigningInput(joseHeader, Encoding.UTF8.GetBytes(payloadJsonNormalized)), Base64urlDecode(signature)).Should().BeTrue();
    }
    
    [Fact]
    public void JwsWithAdditionalProtectedHeadersAndDetachedModeCanBeSerializedWithCompleteSerialization()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.ES256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var payloadJson = @"{
            ""key1"": ""test"",
            ""key2"": ""test2"",
            ""testArray"": [
                {
                    ""complexTest"": ""test"",
                    ""success"": true
                }
            ]
        }";
        var payloadJsonNormalized = Regex.Replace(payloadJson, @"\s+", string.Empty, RegexOptions.Compiled);
        var payload = Encoding.UTF8.GetBytes(payloadJsonNormalized);
        var additionalHeaders = new Dictionary<string, string>()
        {
            {"testKey", "testValue"},
            {"testKey2", "testValue2"},
        };
        
        var joseHeader = new ProtectedJoseHeader(jwk, SerializationOption.JwsCompleteJsonSerialization, "application/json", additionalHeaders);
        var jws = new JWS(new []{joseHeader}, payload, ContentMode.Detached);
        jws.CalculateSignature();
        var jwsCompleteJson = jws.Export();
        var parsedJwsCompleteJson = JObject.Parse(jwsCompleteJson);
        
        var payloadFromJws = parsedJwsCompleteJson.GetValue("payload");
        payloadFromJws.Should().BeNull("Payload should be empty due to detached content mode");
        
        var signatures = (JObject)parsedJwsCompleteJson.GetValue("signatures").First;
        
        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(signatures.GetValue("protected").ToString()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);
        
        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("ES256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(8);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("crv").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterCRV]);
        parsedJwk.GetValue("y").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterY]);
        parsedJwk.GetValue("x").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterX]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE+JSON");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("json");
        parsedProtectedHeader.GetValue("testKey").ToString().Should().Be("testValue");
        parsedProtectedHeader.GetValue("testKey2").ToString().Should().Be("testValue2");
        
        var signature = Encoding.UTF8.GetString(Base64urlDecode(signatures.GetValue("signature").ToString()));
        signature.Length.Should().BePositive("A JWS signature should be present");
    }
    
    [Fact]
    public void JwsWithAdditionalProtectedHeadersAndDetachedModeCanBeSerializedWithFlattenedSerialization()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.ES256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var payloadJson = @"{
            ""key1"": ""test"",
            ""key2"": ""test2"",
            ""testArray"": [
                {
                    ""complexTest"": ""test"",
                    ""success"": true
                }
            ]
        }";
        var payloadJsonNormalized = Regex.Replace(payloadJson, @"\s+", string.Empty, RegexOptions.Compiled);
        var payload = Encoding.UTF8.GetBytes(payloadJsonNormalized);
        var additionalHeaders = new Dictionary<string, string>()
        {
            {"testKey", "testValue"},
            {"testKey2", "testValue2"},
        };
        
        var joseHeader = new ProtectedJoseHeader(jwk, SerializationOption.JwsFlattenedJsonSerialization, "application/json", additionalHeaders);
        var jws = new JWS(new []{joseHeader}, payload, ContentMode.Detached);
        jws.CalculateSignature();
        var jwsFlattenedJson = jws.Export();
        var parsedJwsFlattenedJson = JObject.Parse(jwsFlattenedJson);
        
        var payloadFromJws = parsedJwsFlattenedJson.GetValue("payload");
        payloadFromJws.Should().BeNull("Payload should be empty due to detached content mode");
        
        var headerJson = Encoding.UTF8.GetString(Base64urlDecode(parsedJwsFlattenedJson.GetValue("protected").ToString()));
        headerJson.Length.Should().BePositive("A JWS protected header should be present");
        var parsedProtectedHeader = JObject.Parse(headerJson);
        
        parsedProtectedHeader.TryGetValue("alg", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("jwk", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("kid", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("typ", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("cty", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("testKey", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("testKey2", out var _).Should().BeTrue();
        
        parsedProtectedHeader.GetValue("alg").ToString().Should().Be("ES256");
        parsedProtectedHeader.GetValue("jwk").Children().Count().Should().Be(8);
        var parsedJwk = JObject.Parse(parsedProtectedHeader.GetValue("jwk").ToString());
        parsedJwk.GetValue("kty").ToString().Should().Be(jwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(jwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(jwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedJwk.GetValue("crv").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterCRV]);
        parsedJwk.GetValue("y").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterY]);
        parsedJwk.GetValue("x").ToString().Should().Be(jwk.KeyParameters[KeyParameter.ECKeyParameterX]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(jwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(jwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE+JSON");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("json");
        parsedProtectedHeader.GetValue("testKey").ToString().Should().Be("testValue");
        parsedProtectedHeader.GetValue("testKey2").ToString().Should().Be("testValue2");
        
        var signature = Encoding.UTF8.GetString(Base64urlDecode(parsedJwsFlattenedJson.GetValue("signature").ToString()));
        signature.Length.Should().BePositive("A JWS signature should be present");
    }
}