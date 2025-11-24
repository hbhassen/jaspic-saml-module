# Integration Guide

Step-by-step instructions to integrate the SAML JASPIC module into a Java EE/Jakarta EE application and validate the flow.

## 1. Build the artifacts

```bash
mvn clean package
```

The command builds both the library and the demo WAR.

## 2. Install the module into WildFly

Follow the steps in [MODULE-CONFIG.md](./MODULE-CONFIG.md) to copy the jar files and create `module.xml` under `$WILDFLY_HOME/modules/com/yourcompany/jaspic/saml/main/`.

## 3. Configure `standalone.xml`

Use [`standalone-sample.xml`](./standalone-sample.xml) as a reference. It keeps every default
subsystem shipped in WildFly 31 (Jakarta EE 10 / JDK 17) and adds the `jaspic` element name required
by that release. Ensure that:

* The `auth-module` points to `com.yourcompany.jaspic.saml`.
* Module options define IdP endpoints, keystore path, and `public-paths`.
* The `application-security-domain` references the security domain that activates this auth module.

## 4. Deploy the demo application

Deploy the generated WAR located at `demo-app/target/demo-app.war`.

## 5. Test the endpoints

* `GET /public/hello` should always respond without authentication.
* `GET /secure/profile` should redirect to the IdP login page when not authenticated.
* After successful SAML login, `GET /secure/profile` should return the authenticated user and roles.

Use browser developer tools to inspect the HTTP-POST containing `SAMLResponse` if troubleshooting is required.

## 6. Common error cases

| Symptom | Likely cause | Resolution |
| --- | --- | --- |
| 401 after POST | Signature invalid or IdP certificate mismatch | Verify `idp-cert-path` and refresh metadata |
| Redirect loop | Assertion consumer URL incorrect | Ensure WildFly public URL matches IdP configuration |
| No roles applied | IdP attributes not mapped to `roles`/`groups` | Configure attribute release on IdP |
| Decryption failure | Wrong keystore password or alias | Confirm `keystore-path`, `key-alias`, and passwords |

## 7. Troubleshooting tips

* Enable DEBUG logging for `com.yourcompany.jaspic.saml` to get assertion summaries and flow details.
* Use `keytool -list -v -keystore <path>` to confirm the keystore contents.
* Capture HTTP traffic with browser dev tools or `tcpdump` to verify that the `SAMLResponse` is POSTed correctly.
* Validate the IdP certificate chain to avoid trust issues.

## 8. SAML debugging

OpenSAML exceptions are surfaced in server logs with contextual messages. The `SamlUtils.summarizeResponse` helper can be added to log statements to quickly identify issuer, destination, and assertion count without dumping full XML. Combine this with WildFly access logs to correlate redirects and POST callbacks.
