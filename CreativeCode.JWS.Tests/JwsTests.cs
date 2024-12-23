using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using CreativeCode.JWK.KeyParts;
using Xunit;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using static CreativeCode.JWK.Base64Helper;
using static CreativeCode.JWS.JWS;
using static CreativeCode.JWK.KeyParts.KeyParameter;

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
        var additionalHeaders = new Dictionary<string, object>()
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
        var additionalHeaders = new Dictionary<string, object>()
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
        var additionalHeaders = new Dictionary<string, object>()
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

    [Fact]
    public void CompactJwsWithUnencodedPayloadCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.ES256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var additionalHeaders = new Dictionary<string, object>()
        {
            {"b64", false}
        };
        var criticalHeaders = new List<string>()
        {
            "b64"
        };
        
        var joseHeader = new ProtectedJoseHeader(jwk, SerializationOption.JwsCompactSerialization, "application/json", additionalHeaders, criticalHeaders);
        var payload = Encoding.UTF8.GetBytes("payload");

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
        parsedProtectedHeader.TryGetValue("b64", out var _).Should().BeTrue();
        parsedProtectedHeader.TryGetValue("crit", out var _).Should().BeTrue();
        
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
        parsedProtectedHeader.GetValue("b64").Value<bool>().Should().BeFalse();
        parsedProtectedHeader.GetValue("crit").ToObject<IList<string>>().Should().BeEquivalentTo(new List<string>(){"b64"});

        var payloadFromJws = parts.ElementAt(1);
        payloadFromJws.Length.Should().Be(0, "Payload should be empty due to detached content mode");
        
        var signature = parts.Last();
        signature.Length.Should().BePositive("A JWS signature should be present");

        var publicKey = new JWK.JWK(jwk.Export());
        VerifySignature(publicKey, SigningInput(joseHeader, payload), Base64urlDecode(signature)).Should().BeTrue();
    }
    
    [Fact]
    public void CompactJwsWithUnencodedPayloadWithCompleteSerializationThrowsException()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.ES256;
        var jwk = new JWK.JWK(algorithm, keyUse, keyOperations);
        var additionalHeaders = new Dictionary<string, object>()
        {
            {"b64", false}
        };
        var criticalHeaders = new List<string>()
        {
            "b64"
        };
        
        var joseHeader = new ProtectedJoseHeader(jwk, SerializationOption.JwsCompactSerialization, "application/json", additionalHeaders, criticalHeaders);
        var payload = Encoding.UTF8.GetBytes("payload");

        Assert.Throws<ArgumentException>(() => new JWS(new []{joseHeader}, payload, ContentMode.Complete));
    }

    [Fact]
    public void JwsWithAdditionalProtectedHeadersAndDetachedModeCanBeSerializedWithCompactSerializationWithSafeComplyKey()
    {
        // Load the private key from a .pem
        string testWorkingDirectory = Directory.GetCurrentDirectory();
        var filePathPemPrivateKey = Path.Combine(testWorkingDirectory, "Resources", "safecomply_private.pem");
        var privateKeyPemContent = File.ReadAllText(filePathPemPrivateKey);
        var privateKeyPemBase64 = privateKeyPemContent
            .Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "");
        var privateKeyPemBytes = Convert.FromBase64String(privateKeyPemBase64);
        using var ecP256PrivateKey = ECDsa.Create();
        ecP256PrivateKey.ImportPkcs8PrivateKey(privateKeyPemBytes, out _);

        // Select keyType, keyUse and keyOperations manually for the private key, we know them based on the use case
        var keyTypePrivateKey = KeyType.EllipticCurve;
        var keyUsePrivateKey = PublicKeyUse.Signature;
        var keyOperationsPrivateKey = new HashSet<KeyOperation>(new[]
            {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithmPrivateKey = Algorithm.ES256;

        // Extract keyParameters from private key
        var ecP26PrivateKeyParameters = ecP256PrivateKey.ExportParameters(true);
        var privateKeyD = Base64urlEncode(ecP26PrivateKeyParameters.D);
        var publicKeyX = Base64urlEncode(ecP26PrivateKeyParameters.Q.X);
        var publicKeyY = Base64urlEncode(ecP26PrivateKeyParameters.Q.Y);

        var keyLength =
            Algorithm.ES256.Name.Split(new string[] {"ES"}, StringSplitOptions.None)[1]; // Algorithm = 'ES' + Keylength
        var curveName = "P-" + keyLength;
        var keyParametersPrivateKey = new Dictionary<KeyParameter, string>
        {
            {ECKeyParameterCRV, curveName},
            {ECKeyParameterX, publicKeyX},
            {ECKeyParameterY, publicKeyY},
            {ECKeyParameterD, privateKeyD}
        };

        using var sha256 = SHA256.Create();
        var ecP256PrivateKeyHash = sha256.ComputeHash(privateKeyPemBytes);
        var keyIdPrivateKey = BitConverter.ToString(ecP256PrivateKeyHash).Replace("-", "").ToLower();

        var privateKeyJwk = new JWK.JWK(keyTypePrivateKey, keyParametersPrivateKey, keyUsePrivateKey, keyOperationsPrivateKey, algorithmPrivateKey, keyIdPrivateKey);
        
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
        var additionalHeaders = new Dictionary<string, object>()
        {
            {"testKey", "testValue"},
            {"testKey2", "testValue2"},
            {"b64", false}
        };
        var criticalHeaders = new List<string>()
        {
            "b64"
        };
        
        var joseHeader = new ProtectedJoseHeader(privateKeyJwk, SerializationOption.JwsCompactSerialization, "application/json", additionalHeaders, criticalHeaders);
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
        parsedJwk.GetValue("kty").ToString().Should().Be(privateKeyJwk.KeyType.Type);
        parsedJwk.GetValue("use").ToString().Should().Be(privateKeyJwk.PublicKeyUse.KeyUse);
        parsedJwk.GetValue("alg").ToString().Should().Be(privateKeyJwk.Algorithm.Name);
        parsedJwk.GetValue("kid").ToString().Should().Be(privateKeyJwk.KeyID);
        parsedJwk.GetValue("crv").ToString().Should().Be(privateKeyJwk.KeyParameters[KeyParameter.ECKeyParameterCRV]);
        parsedJwk.GetValue("y").ToString().Should().Be(privateKeyJwk.KeyParameters[KeyParameter.ECKeyParameterY]);
        parsedJwk.GetValue("x").ToString().Should().Be(privateKeyJwk.KeyParameters[KeyParameter.ECKeyParameterX]);
        parsedJwk.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(privateKeyJwk.KeyOperations.Select(op => op.Operation));
        parsedProtectedHeader.GetValue("kid").ToString().Should().Be(privateKeyJwk.KeyID);
        parsedProtectedHeader.GetValue("typ").ToString().Should().Be("JOSE");
        parsedProtectedHeader.GetValue("cty").ToString().Should().Be("json");
        parsedProtectedHeader.GetValue("testKey").ToString().Should().Be("testValue");
        parsedProtectedHeader.GetValue("testKey2").ToString().Should().Be("testValue2");

        var payloadFromJws = parts.ElementAt(1);
        payloadFromJws.Length.Should().Be(0, "Payload should be empty due to detached content mode");
        
        var signature = parts.Last();
        signature.Length.Should().BePositive("A JWS signature should be present");
        
        // Select keyType, keyUse and keyOperations manually for the public key, we know them based on the use case
        var keyTypePublicKey = KeyType.EllipticCurve;
        var keyUsePublicKey = PublicKeyUse.Signature;
        var keyOperationsPublicKey = new HashSet<KeyOperation>(new[]
            {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithmPubliceKey = Algorithm.ES256;
        
        var filePathPemPublicKeyCert = Path.Combine(testWorkingDirectory, "Resources", "safecomply_certificate.crt");
        var publicKeyCert = new X509Certificate2(filePathPemPublicKeyCert);
        var ecP256PublicKey = publicKeyCert.GetECDsaPublicKey();
        var ecP256PublicKeyParameters = ecP256PublicKey.ExportParameters(false);
        publicKeyX = Base64urlEncode(ecP256PublicKeyParameters.Q.X);
        publicKeyY = Base64urlEncode(ecP256PublicKeyParameters.Q.Y);
        var keyParametersPublicKey = new Dictionary<KeyParameter, string>
        {
            {ECKeyParameterCRV, curveName},
            {ECKeyParameterX, publicKeyX},
            {ECKeyParameterY, publicKeyY}
        };
        
        var publicKey = publicKeyCert.GetPublicKey();
        using var sha1 = System.Security.Cryptography.SHA1.Create();
        var ski = BitConverter.ToString(sha1.ComputeHash(publicKey)).Replace("-", ":");
        
        var publicKeyJwk = new JWK.JWK(keyTypePublicKey, keyParametersPublicKey, keyUsePublicKey, keyOperationsPublicKey, algorithmPubliceKey, ski);
        
        VerifySignature(publicKeyJwk, SigningInput(joseHeader, Encoding.UTF8.GetBytes(payloadJsonNormalized)), Base64urlDecode(signature)).Should().BeTrue();
    }
}