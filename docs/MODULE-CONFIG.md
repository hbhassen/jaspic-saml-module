# WildFly module installation

This document explains how to package the `jaspic-saml-module` as a WildFly module and wire it into a security domain using Elytron's built-in JASPI support. The configuration stays within the standard Elytron and Undertow subsystems—no `org.wildfly.extension.jaspic` extension or preview layer is required on WildFly 31.

## Build and copy the JAR

1. Build the library:
   ```bash
   mvn -pl jaspic-saml-module clean package
   ```
2. Copy `jaspic-saml-module/target/jaspic-saml-module-1.0.0-SNAPSHOT.jar` and all its runtime dependencies (`opensaml-*`, `xmlsec`, `bcprov`, `slf4j-api`) into a module folder, for example:
   ```
   $WILDFLY_HOME/modules/com/yourcompany/jaspic/saml/main/
   ```

## Create `module.xml`

Place the following descriptor next to the jar files. The Jakarta EE 10 module names shipped with
WildFly 31 are used to stay compatible with JDK 17 and the default distribution:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<module xmlns="urn:jboss:module:1.9" name="com.yourcompany.jaspic.saml">
    <resources>
        <resource-root path="jaspic-saml-module-1.0.0-SNAPSHOT.jar"/>
        <!-- add the copied dependencies as resource-root entries -->
    </resources>
   <dependencies>
        <module name="jakarta.security.auth.message.api"/>
        <module name="jakarta.servlet.api"/>
        <module name="org.slf4j"/>
   </dependencies>
</module>
```

## Declare the JASPIC auth-module

In `standalone.xml`, configure the module inside Elytron's `<jaspi>` block and enable JASPI for Undertow's application security domain. The key fragments look like this (full example in `standalone-sample.xml`):

```xml
<subsystem xmlns="urn:wildfly:elytron:18.0" final-providers="combined-providers" disallowed-providers="OracleUcrypto">
    <!-- providers, security-realms, security-domains omitted for brevity -->
    <jaspi>
        <jaspi-configuration name="jaspi-test" layer="HttpServlet">
            <server-auth-modules>
                <server-auth-module class-name="com.yourcompany.jaspic.saml.SamlServerAuthModule" module="com.yourcompany.jaspic.saml" flag="REQUIRED">
                    <options>
                        <property name="sp-entity-id" value="saml-sp"/>
                        <property name="registration-id" value="saml-sp"/>
                        <property name="idp-entity-id" value="https://localhost:8443/realms/saml-realm"/>
                        <property name="idp-sso-url" value="https://localhost:8443/realms/saml-realm/protocol/saml"/>
                        <property name="keystore-path" value="src/main/resources/keystore.jks"/>
                        <property name="keystore-password" value="changeit"/>
                        <property name="key-alias" value="samlkey"/>
                        <property name="key-password" value="changeit"/>
                        <property name="idp-cert-path" value="src/main/resources/idp.crt"/>
                        <property name="public-paths" value="/,/error,/public/**"/>
                    </options>
                </server-auth-module>
            </server-auth-modules>
        </jaspi-configuration>
    </jaspi>
</subsystem>

<subsystem xmlns="urn:jboss:domain:undertow:14.0" default-security-domain="other">
    <!-- listeners omitted for brevity -->
    <application-security-domains>
        <application-security-domain name="other" security-domain="ApplicationDomain" enable-jaspi="true" integrated-jaspi="false"/>
    </application-security-domains>
</subsystem>
```

The Elytron security domain referenced by Undertow (`ApplicationDomain` above) must include the realms that should receive the authenticated principal. Set `enable-jaspi="true"` to allow the `SamlServerAuthModule` to drive the HTTP authentication flow, and leave `integrated-jaspi="false"` so the custom module remains in control of redirects and assertion processing.

## Logging

Add a logger category for `com.yourcompany.jaspic.saml` (e.g., level `DEBUG`) in the logging subsystem to trace SAML exchanges and module lifecycle events while validating the setup.
