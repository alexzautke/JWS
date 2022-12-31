using System.Text;
using CreativeCode.JWK.KeyParts;
using Xunit;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using static CreativeCode.JWK.Base64Helper;

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

        var jws = new JWS(joseHeader, payload);
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
        
        var signature = Encoding.UTF8.GetString(Base64urlDecode(parts.Last()));
        signature.Length.Should().BePositive("A JWS signature should be present");
    }
}