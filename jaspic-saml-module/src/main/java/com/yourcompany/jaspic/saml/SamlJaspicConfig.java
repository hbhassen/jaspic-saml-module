package com.yourcompany.jaspic.saml;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Immutable configuration holder for the SAML JASPIC module.
 * <p>
 * Values are resolved using the following precedence:
 * <ol>
 *     <li>Module options provided by the JASPIC runtime (for example through {@code module-options} in
 *     {@code standalone.xml}).</li>
 *     <li>Fallback to JVM system properties, which is convenient when bootstrapping the module outside of a
 *     full WildFly domain.</li>
 * </ol>
 * The class performs light validation and exposes helper methods for path checks and resource resolution.
 */
public final class SamlJaspicConfig {

    private final String spEntityId;
    private final String idpEntityId;
    private final String idpSsoUrl;
    private final Path keystorePath;
    private final char[] keystorePassword;
    private final String keyAlias;
    private final char[] keyPassword;
    private final Path idpCertificatePath;
    private final List<String> publicPaths;

    private SamlJaspicConfig(
            String spEntityId,
            String idpEntityId,
            String idpSsoUrl,
            Path keystorePath,
            char[] keystorePassword,
            String keyAlias,
            char[] keyPassword,
            Path idpCertificatePath,
            List<String> publicPaths) {
        this.spEntityId = Objects.requireNonNull(spEntityId, "Service Provider entity ID is required");
        this.idpEntityId = Objects.requireNonNull(idpEntityId, "Identity Provider entity ID is required");
        this.idpSsoUrl = Objects.requireNonNull(idpSsoUrl, "Identity Provider SSO URL is required");
        this.keystorePath = Objects.requireNonNull(keystorePath, "Keystore path is required");
        this.keystorePassword = keystorePassword;
        this.keyAlias = Objects.requireNonNull(keyAlias, "Key alias is required");
        this.keyPassword = keyPassword;
        this.idpCertificatePath = Objects.requireNonNull(idpCertificatePath, "IdP certificate path is required");
        this.publicPaths = Collections.unmodifiableList(new ArrayList<>(publicPaths));
    }

    /**
     * Factory that reads configuration keys from the provided module options and system properties.
     * Supported keys match the names used in {@code standalone.xml}:
     * <ul>
     *     <li>{@code sp-entity-id}</li>
     *     <li>{@code idp-entity-id}</li>
     *     <li>{@code idp-sso-url}</li>
     *     <li>{@code keystore-path}</li>
     *     <li>{@code keystore-password}</li>
     *     <li>{@code key-alias}</li>
     *     <li>{@code key-password}</li>
     *     <li>{@code idp-cert-path}</li>
     *     <li>{@code public-paths} (comma separated)</li>
     * </ul>
     *
     * @param moduleOptions map of options passed by the JASPIC runtime, may be {@code null}
     * @return resolved configuration instance
     */
    public static SamlJaspicConfig from(Map<String, ?> moduleOptions) {
        Map<String, ?> options = moduleOptions == null ? Collections.emptyMap() : moduleOptions;

        String spEntityId = readOption("sp-entity-id", options)
                .orElseThrow(() -> new IllegalArgumentException("Missing sp-entity-id"));
        String idpEntityId = readOption("idp-entity-id", options)
                .orElseThrow(() -> new IllegalArgumentException("Missing idp-entity-id"));
        String idpSsoUrl = readOption("idp-sso-url", options)
                .orElseThrow(() -> new IllegalArgumentException("Missing idp-sso-url"));

        Path keystorePath = Path.of(readOption("keystore-path", options)
                .orElseThrow(() -> new IllegalArgumentException("Missing keystore-path")));
        char[] keystorePassword = readOption("keystore-password", options)
                .orElse("changeit")
                .toCharArray();
        String keyAlias = readOption("key-alias", options)
                .orElseThrow(() -> new IllegalArgumentException("Missing key-alias"));
        char[] keyPassword = readOption("key-password", options)
                .orElse(String.valueOf(keystorePassword))
                .toCharArray();
        Path idpCertPath = Path.of(readOption("idp-cert-path", options)
                .orElseThrow(() -> new IllegalArgumentException("Missing idp-cert-path")));

        List<String> publicPaths = readOption("public-paths", options)
                .map(SamlJaspicConfig::splitPaths)
                .orElseGet(List::of);

        return new SamlJaspicConfig(
                spEntityId,
                idpEntityId,
                idpSsoUrl,
                keystorePath,
                keystorePassword,
                keyAlias,
                keyPassword,
                idpCertPath,
                publicPaths);
    }

    private static List<String> splitPaths(String value) {
        String[] tokens = value.split(",");
        List<String> result = new ArrayList<>();
        for (String token : tokens) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    private static Optional<String> readOption(String key, Map<String, ?> moduleOptions) {
        if (moduleOptions != null && moduleOptions.containsKey(key)) {
            Object value = moduleOptions.get(key);
            if (value != null) {
                String asString = String.valueOf(value).trim();
                if (!asString.isEmpty()) {
                    return Optional.of(asString);
                }
            }
        }
        String sysValue = System.getProperty(key);
        if (sysValue != null && !sysValue.isBlank()) {
            return Optional.of(sysValue.trim());
        }
        return Optional.empty();
    }

    /**
     * Performs a simple wildcard check against the configured public paths.
     * Supports exact matches (e.g. {@code /public/status}), prefix matches with {@code /**}
     * and trailing wildcard {@code *} for single path segment matches.
     *
     * @param requestPath normalized request path
     * @return {@code true} when the path should bypass SAML authentication
     */
    public boolean isPublicPath(String requestPath) {
        String path = Optional.ofNullable(requestPath).orElse("");
        for (String pattern : publicPaths) {
            if (matches(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    private boolean matches(String pattern, String path) {
        if ("**".equals(pattern)) {
            return true;
        }
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.startsWith(prefix);
        }
        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return path.startsWith(prefix) && path.substring(prefix.length()).split("/").length <= 2;
        }
        if (pattern.contains("*")) {
            String regex = pattern.replace(".", "\\.").replace("*", ".*");
            return path.matches(regex);
        }
        return pattern.equals(path);
    }

    /**
     * Convenience check to ensure the configured files are reachable, useful when validating a server setup at boot time.
     *
     * @return list of human readable warnings; empty when everything looks valid
     */
    public List<String> validatePaths() {
        List<String> warnings = new ArrayList<>();
        if (!Files.exists(keystorePath)) {
            warnings.add("Keystore not found at " + keystorePath);
        }
        if (!Files.exists(idpCertificatePath)) {
            warnings.add("IdP certificate not found at " + idpCertificatePath);
        }
        return warnings;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getIdpSsoUrl() {
        return idpSsoUrl;
    }

    public Path getKeystorePath() {
        return keystorePath;
    }

    public char[] getKeystorePassword() {
        return keystorePassword.clone();
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public char[] getKeyPassword() {
        return keyPassword.clone();
    }

    public Path getIdpCertificatePath() {
        return idpCertificatePath;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    @Override
    public String toString() {
        return "SamlJaspicConfig{" +
                "spEntityId='" + spEntityId + '\'' +
                ", idpEntityId='" + idpEntityId + '\'' +
                ", idpSsoUrl='" + idpSsoUrl + '\'' +
                ", keystorePath=" + keystorePath +
                ", keyAlias='" + keyAlias + '\'' +
                ", idpCertificatePath=" + idpCertificatePath +
                ", publicPaths=" + publicPaths.stream().collect(Collectors.joining(",")) +
                '}';
    }
}
