# Demo application

Minimal Jakarta EE WAR showcasing the SAML JASPIC module. The application exposes two endpoints:

* `GET /public/hello` – no authentication required.
* `GET /secure/profile` – requires SAML authentication and returns the authenticated user and roles.

## Building

```bash
mvn -pl demo-app clean package
```

## Deploying

1. Install and configure the `jaspic-saml-module` as described in `../docs`.
2. Deploy the generated `demo-app.war` to WildFly 31.
3. Ensure the application is associated with the `jaspic-saml` security domain configured in `standalone-sample.xml`.

## Testing

* Call `http://localhost:8080/demo-app/public/hello` to verify the public endpoint.
* Call `http://localhost:8080/demo-app/secure/profile` to trigger a redirect to the Identity Provider. After successful login, the endpoint returns JSON with the principal name and roles.

The REST resources are intentionally simple and heavily commented so you can focus on the JASPIC module behaviour.
