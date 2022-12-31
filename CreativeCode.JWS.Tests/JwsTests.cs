using System.Text;
using CreativeCode.JWK.KeyParts;
using Xunit;

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
        var json = jws.Export();
    }
}