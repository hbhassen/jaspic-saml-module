# JASPIC SAML Module

This library provides a standalone JASPIC `ServerAuthModule` that authenticates HTTP requests against a SAML v2 Identity Provider without relying on Spring Security. It is designed for WildFly 31 running on JDK 17 and can also be reused by other Java EE/Jakarta EE servers that support the JASPIC specification.

## Role of the library

The module intercepts incoming requests and enforces SAML-based authentication. When a protected endpoint is requested and no SAML assertion is present, the user is redirected to the configured IdP. When a signed SAMLResponse arrives (HTTP-POST binding), the module validates the signature, decrypts assertions if needed, maps attributes to roles, and establishes a `Principal` on the application subject.

## Architecture

* **SamlServerAuthModule**: JASPIC entry point that orchestrates redirects, response handling, and subject population.
* **SamlJaspicConfig**: Reads module options (from `standalone.xml` or system properties) and exposes convenience helpers such as public path matching.
* **SamlUtils**: Wraps OpenSAML 4 initialization, parsing, signature validation, decryption, and subject extraction.
* **Resources**: Keystore and IdP certificate files referenced by configuration to secure exchanges.

## Functional flow

1. Request arrives on WildFly.
2. `SamlServerAuthModule` checks whether the path is public. If not, it looks for a `SAMLResponse` parameter.
3. Absent a response, the module redirects to the IdP SSO endpoint with RelayState tracking.
4. The IdP authenticates the user and posts a signed SAMLResponse back to the application ACS endpoint.
5. The module decodes and validates the response, decrypts assertions (when encrypted), and extracts the subject and roles.
6. The JASPIC callbacks build the caller `Principal` and associated groups so the application can rely on standard container authorization.
7. Logout requests simply clear the subject to avoid stale sessions.

## JASPIC lifecycle

* **initialize**: Called once during module boot. OpenSAML is initialized and configuration is validated.
* **validateRequest**: Executed per incoming request. It enforces public path bypass, logout cleanup, redirect to IdP, or SAML response processing.
* **secureResponse**: Allows the module to modify the outbound response (not required in this module, simply returns success).
* **cleanSubject**: Clears credentials when the container asks for it.

## SSO sequence diagram

```
Client -> Application : Request /secure/profile
Application -> IdP : Redirect to SSO URL with RelayState
IdP -> Client : Presents login form
Client -> IdP : Submits credentials
IdP --> Client : Issues SAMLResponse (POST)
Client -> Application : POST SAMLResponse
Application -> IdP : Validate signature using IdP cert
Application -> Keystore : Decrypt assertion with SP key
Application -> Application : Create Principal + roles
Application -> Client : Grant access to /secure/profile
```

## Keystore usage

The Service Provider (SP) private key is stored in a Java Keystore (JKS or PKCS12). The module loads it using `keystore-path`, `keystore-password`, `key-alias`, and `key-password`. The key decrypts encrypted assertions and can also be used when signing SP-initiated logout requests.

## Identity Provider certificate

The IdP signing certificate is provided through `idp-cert-path`. It must contain the public certificate used by the IdP to sign responses. The module validates every signature with this certificate; unsigned responses are rejected.

## Security domain

WildFly associates the module with a security domain. The domain defines how authentication results map to authorization checks in deployed applications. The roles extracted from SAML attributes become groups inside the security domain, enabling declarative access control via `@RolesAllowed` and web.xml constraints.

## Auth-module

The `auth-module` declaration in `standalone.xml` points to the custom module installed in WildFly. Module options inject configuration such as IdP endpoints, keystore location, and public paths so no code changes are needed when moving between environments.

## Public paths

`public-paths` allows configuring URL prefixes or explicit resources that bypass authentication (e.g., health checks or static content). Patterns accept literal paths, `/*`, and `/**` wildcards.

## standalone.xml configuration

See [`standalone-sample.xml`](./standalone-sample.xml) for a complete, copy-pastable configuration that includes `auth-module` wiring, module options, and security-domain activation.
