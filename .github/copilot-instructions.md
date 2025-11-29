## Quick context

This repository provides a standalone JASPIC ServerAuthModule that performs SAML v2 authentication
for Jakarta EE/WildFly apps (targeted at WildFly 31 / JDK 17). The module is self-contained under
`jaspic-saml-module` and a minimal demo WAR is available in `demo-app`.

Key files to inspect:
- `jaspic-saml-module/src/main/java/com/yourcompany/jaspic/saml/SamlServerAuthModule.java` (JASPIC entrypoint)
- `jaspic-saml-module/src/main/java/com/yourcompany/jaspic/saml/SamlJaspicConfig.java` (module options parsing)
- `jaspic-saml-module/src/main/java/com/yourcompany/jaspic/saml/SamlUtils.java` (OpenSAML helpers)
- `docs/standalone-sample.xml` and `docs/MODULE-CONFIG.md` (WildFly wiring and module.xml example)
- `demo-app/src/main/java/com/yourcompany/demo/*` (public vs protected endpoints usage examples)

Build & run notes (concrete commands)
- Build everything: `mvn clean package` (top-level)
- Build only library: `mvn -pl jaspic-saml-module clean package`
- Build only demo: `mvn -pl demo-app clean package`
- Demo WAR: `demo-app/target/demo-app.war`
- Module jar (fat jar / shaded): `jaspic-saml-module/target/jaspic-saml-module-1.0.0-SNAPSHOT-all.jar` (copy into WildFly module folder)

Project-specific conventions & patterns for code edits
- Configuration precedence: `SamlJaspicConfig.from(Map)` reads JASPIC module options first, then JVM system properties. Use those keys when adding tests or docs: `sp-entity-id`, `idp-sso-url`, `keystore-path`, `idp-cert-path`, `public-paths`, etc.
- Public path matching: `SamlJaspicConfig.isPublicPath` supports exact, `/*` and `/**` patterns. Tests and changes must preserve that behavior.
- Role extraction: `SamlServerAuthModule.extractRoles(...)` recognizes attributes named `roles`, `role`, or `groups` and falls back to `user` when none present. Keep that mapping if adjusting attribute handling.
- OpenSAML lifecycle: `SamlUtils.initializeOpenSaml()` is idempotent and must be called before any OpenSAML operation. Avoid re-initializing in tests.
- Keystore handling: code reads SP key/cert directly from configured `keystore-path`; module.xml must include `java.xml` dependency (see `docs/MODULE-CONFIG.md`).

Integration hints and debugging
- WildFly: enable `enable-jaspi="true"` and set `integrated-jaspi="false"` in the `application-security-domain` when using the sample `standalone-sample.xml`.
- To reproduce locally, build the shaded jar, install as module under `$WILDFLY_HOME/modules/com/yourcompany/jaspic/saml/main/`, and update `standalone.xml` per `docs/standalone-sample.xml`.
- Logs: enable DEBUG for `com.yourcompany.jaspic.saml` to see AuthnRequest/Response summaries. The helper `SamlUtils.summarizeResponse(response)` produces compact assertion summaries for safe logging.
- Common failure modes are documented in `docs/INTEGRATION-GUIDE.md` (signature mismatch, decryption failures, wrong ACS, missing roles). Use the table there when triaging.

Testing notes
- Unit tests for OpenSAML helpers live in `jaspic-saml-module/src/test/java/...` (e.g., `SamlUtilsTest`). Run via `mvn -pl jaspic-saml-module test`.
- Tests avoid network calls and focus on object creation/parsing. If you add tests that require certificates/keystores, include small test fixtures under `src/test/resources` and update `pom.xml` test resources accordingly.

What an AI assistant should do first when asked to change SAML logic
1. Read `SamlServerAuthModule` to understand where request validation, redirect, and response handling happen.
2. Check `SamlJaspicConfig` for configuration keys and `public-paths` behavior — changes to matching must be reflected in docs and tests.
3. Inspect `SamlUtils` for OpenSAML plumbing (parsing, signature validation, decryption). Reuse helpers rather than duplicating low-level XML handling.
4. Run the module unit tests (`mvn -pl jaspic-saml-module test`) before and after edits.

Small code examples (copy-paste safe)
- Triggering a redirect (see `SamlServerAuthModule.triggerIdentityProviderRedirect`): uses `SamlUtils.buildAuthnRequest(...)`, `SamlUtils.signAuthnRequest(...)`, `SamlUtils.deflateAndBase64Encode(...)` and appends `SAMLRequest` + `RelayState` to `idp-sso-url`.
- Validating a response (see `handleSamlResponse`): parse with `SamlUtils.parseSamlResponse`, validate with `SamlUtils.validateSignature`, decrypt with `SamlUtils.decryptAssertionsIfNeeded`, extract user with `SamlUtils.extractSubject`.

Edge cases & constraints (important to preserve)
- The module intentionally falls back to a default role `user` when no role attributes are present — changing this affects authorization semantics in deployed apps.
- `SamlJaspicConfig.validatePaths()` may emit warnings at startup if keystore or idp certificate paths are missing; preserve this early feedback for operators.
- The code expects the response to be signed; unsigned responses are rejected by `SamlUtils.validateSignature`.

If anything is unclear or you need CI/credential details (IdP metadata, keystore passwords used by CI), ask the maintainer — do NOT assume secrets or real IdP endpoints.

Next step: I can open a PR creating this file (done). Tell me if you want additional rules (e.g., commit message templates, CI steps, or examples for rotating keystore entries) and I will iterate.
