# C# JWSs - JSON Web Signature (RFC7515)
This repository provides an implementation in C# of RFC7515 (JSON Web Signature).

`Notice: The current implementation has been used in a production environment.` 
<br>`However, no support will be offered for this project. Here be dragons. Please fill any bugs you may find.`

## Getting Started

JSON Web Signature (JWS) represents content secured with digital
   signatures or Message Authentication Codes (MACs) using JSON-based
   data structures.

All details of the implementation are based on the following literature:
* [RFC 7517 - JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.txt)
* [RFC 7518 - JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.txt)

Supported algorithms for creating a digital signature / MAC:

|                | Algorithm | Support |
|----------------|:-----------------------------|:-------------------------------|
| RSA            | RS256, RS384, RS512          | :x:
| Eliptic Curves | ES256, ES384, ES512          | :negative_squared_cross_mark:
| HMAC           | HS256, HS384, HS512          | :negative_squared_cross_mark:
| None           | none                         | :x: 

|                               | Meaning |
|-------------------------------|:-------------                         |
| :white_check_mark:            | Fully implemented and tested           |
| :negative_squared_cross_mark: | Currently being implemented / Untested |
| :x:                           | Not implemented yet                    |

## Build

The following configuration has been succesfully tested for building and running the project:
* Visual Studio for Mac - Version 8.0
* .Net Core - Version 2.1.302

[![Build Status](https://travis-ci.com/alexzautke/JWS.svg?branch=master)](https://travis-ci.com/alexzautke/JWS)

## Limitations

### Project TODOs
- [] Complete support for all JWK key types
- [] Support for JWS JSON serialization
- [] Support for JWS Unprotected Header values
- [] Support for Public Header Parameter Names
- [] Support for Private Header Parameter Names
- [] Support for x5u, x5c, x5t, x5t#S256 header parameters
- [] Support for "jku" header parameter
- [] Support for "crit" header parameter

- [] Support for jku, x5u, x5c, x5t, x5t#S256, crit parameters in a protected JoseHeader

### Documentation
- [] INSTALL documentation
- [] Security Conciderations
- [] Describe how to run tests (Test section)

## Usage

See [JWS Example](https://gist.github.com/alexzautke/5aafda0cb1da8f17d0a8973512a066e9)

## Security Conciderations

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details 
