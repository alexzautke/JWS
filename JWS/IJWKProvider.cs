using System;
namespace CreativeCode.JWS
{
    public interface IJWKProvider
    {
        string Algorithm();
        string PublicJWK();
        string PrivateJWK();
        string KeyId();
        string KeyType();
    }
}
