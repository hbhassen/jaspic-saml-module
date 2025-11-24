# WildFly module installation

This document explains how to package the `jaspic-saml-module` as a WildFly module and wire it into a security domain.

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

## Register the auth-module in WildFly CLI

```bash
$WILDFLY_HOME/bin/jboss-cli.sh --connect <<'EOC'
/subsystem=security/security-domain=jaspic-saml:add(cache-type=default)
/subsystem=security/security-domain=jaspic-saml/authentication=classic:add()
/subsystem=security/security-domain=jaspic-saml/authentication=classic/login-module=jaspic-saml:add(code=Dummy,flag=optional)
/subsystem=elytron/custom-realm=jaspic-saml-realm:add(module=org.wildfly.security.sasl, flags=["pass-through"])
EOC
```

The above commands remain useful when bridging a legacy security domain, but the recommended
WildFly 31 setup uses the `jaspic` subsystem shown in `standalone-sample.xml` so that default
subsystems stay untouched.

The dummy login module keeps the legacy security domain satisfied while the real authentication is performed by JASPIC.

## Declare the JASPIC auth-module

In `standalone.xml`, under the `undertow` subsystem, add:

```xml
<application-security-domains>
    <application-security-domain name="jaspic-saml" http-authentication-factory="jaspic-saml-http"/>
</application-security-domains>
```

Then define the HTTP authentication factory using Elytron + JASPIC bridge:

```xml
<http-authentication-factory name="jaspic-saml-http" http-server-mechanism-factory="global" security-domain="jaspic-saml-domain">
    <mechanism-configuration>
        <mechanism mechanism-name="BASIC"/>
        <mechanism mechanism-name="FORM"/>
        <mechanism mechanism-name="GLOBAL"/>
    </mechanism-configuration>
</http-authentication-factory>
```

Finally, declare the `auth-module` using the `jaspic` subsystem (the element name replaces the older `jsr196-configuration` that is no longer used in WildFly 31). Module options configure IdP metadata, keystore location, and public paths. See `standalone-sample.xml` for the recommended Jakarta EE 10 snippet that keeps the default WildFly subsystems intact.
