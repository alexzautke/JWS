# CreativeCode.JWK Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.7.0 - 2025-02-23
### Added
- Add ```byte[] SigningInput(ProtectedJoseHeader protectedJoseHeader, byte[] payload)``` on JWS to facilitate the calculation of detached content

## 0.6.0 - 2024-12-23

### Added
- Added support for the 'crit' header as part of the ProtectedJoseHeader. An IReadOnlyList can be passed as part of the JWS constructor to provide the list of all critical header values. Validation of the 'crit' values is performed according to RFC7515.
- Added support for unencoded payloads when collecting the signature input. The 'b64' unencoded payload option can be used according to RFC7797. The signature input will be generated depending on the 'b64' header value automatically.

### Changed
- The IReadOnlyDictionary for the additionalHeaders as part of the ProtectedJoseHeader is now represented as IReadOnlyDictionary<string, object> instead of IReadOnlyDictionary<string, string> to allow for all possible JSON values.

## 0.5.0 - 2024-10-04

### Added
- Added ``ContentMode`` parameter to JWS constructor to support the Detached serialization based on [RFC7517 - Appendix F](https://www.rfc-editor.org/rfc/rfc7515#appendix-F). The default remains a complete serialization.
- Added ```public ProtectedJoseHeader(JWK.JWK jwk, SerializationOption serializationOption, string contentType = null, IReadOnlyDictionary<string, string> additionalHeaders = null)``` to pass in additional string-based key/value pairs to be inlcuded in the Protected header

## 0.4.0 - 2024-08-15

### Fixed
- Fixed KeyNotFoundException in case a JWS was verified using public key information only

## 0.3.1 - 2023-02-08

### Fixed
- Fix JsonWriterException when exporting JWS in parallel

## 0.3.0 - 2023-01-10

### Added
- Add ```VerifySignature(JWK.JWK jwk, byte[] data, byte[] signature)```

## 0.2.0 - 2023-01-01

### Added
- Added support for flattened and complete JSON JWS serialization
- Added support for RSA signatures
- Added support for mulitple protected JoseHeader parameters and corresponding signatures

### Changed
- SerializeJWSWithOptions has been removed in favour of two public methods ``Èxport`` and ``ComputeSignature``

## 0.1.0 - 2019-01-09

### Added
- Initial release of NuGet package.
