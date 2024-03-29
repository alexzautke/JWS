# CreativeCode.JWK Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.3.1 - 2023-02-08

### Fixed
- Fix JsonWriterException when exporting JWS in parallel

## 0.3.0 - 2023-01-10

### Added
- Add VerifySignature(JWK.JWK jwk, byte[] data, byte[] signature)

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
