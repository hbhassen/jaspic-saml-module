package com.yourcompany.jaspic.saml;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.auth.message.callback.GroupPrincipalCallback;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.opensaml.security.x509.BasicX509Credential;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * {@link ServerAuthModule} implementation that delegates authentication to an external SAML v2 Identity Provider.
 * The module is purposely self contained (no Spring dependencies) and is tailored for WildFly 31 but remains portable
 * to other JASPIC compliant runtimes.
 *
 * <p>High level behaviour:</p>
 * <ul>
 *     <li>Skips authentication for public paths configured via {@link SamlJaspicConfig}.</li>
 *     <li>When a {@code SAMLResponse} is posted, the response is parsed, signature validated and assertions decrypted
 *     before a {@link Principal} and optional roles are created on the caller subject.</li>
 *     <li>When authentication is required but no response is present, the user is redirected to the IdP SSO endpoint</li>
 *     <li>Supports simple logout by clearing the subject on {@code /logout}.</li>
 * </ul>
 */
public class SamlServerAuthModule implements ServerAuthModule {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlServerAuthModule.class);
    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[]{HttpServletRequest.class, HttpServletResponse.class};

    private CallbackHandler callbackHandler;
    private SamlJaspicConfig config;

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        this.callbackHandler = Objects.requireNonNull(handler, "CallbackHandler is required");
        this.config = SamlJaspicConfig.from(options);

        try {
            SamlUtils.initializeOpenSaml();
            List<String> warnings = config.validatePaths();
            warnings.forEach(message -> LOGGER.warn("Configuration warning: {}", message));
            LOGGER.info("Initialized SAML JASPIC module with SP entityId {}", config.getSpEntityId());
        } catch (SamlProcessingException e) {
            throw new AuthException("Failed to initialize OpenSAML: " + e.getMessage());
        }
    }

    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES.clone();
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
        String path = normalizePath(request);

        // Fast path: static resources or health endpoints may be configured as public.
        if (config.isPublicPath(path)) {
            LOGGER.debug("Skipping SAML authentication for public path {}", path);
            return AuthStatus.SUCCESS;
        }

        // Lightweight logout handling keeps the interaction stateless.
        if (isLogoutRequest(path)) {
            clearSubject(clientSubject);
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return AuthStatus.SEND_SUCCESS;
        }

        String samlResponseParam = request.getParameter("SAMLResponse");
        if (samlResponseParam != null && !samlResponseParam.isBlank()) {
            return handleSamlResponse(clientSubject, response, samlResponseParam);
        }
        LOGGER.info("At this stage authentication is required  for public path {}", path);
        // At this stage authentication is required but no assertion is present: trigger redirect to the IdP.
        triggerIdentityProviderRedirect(request, response);
        return AuthStatus.SEND_CONTINUE;
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        // Nothing to add to the response; simply indicate success.
        return AuthStatus.SEND_SUCCESS;
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        clearSubject(subject);
    }

    private AuthStatus handleSamlResponse(Subject clientSubject, HttpServletResponse response, String samlResponseParam) throws AuthException {
        try {
            Response samlResponse = SamlUtils.parseSamlResponse(samlResponseParam);
            X509Certificate idpCertificate = SamlUtils.loadCertificate(config.getIdpCertificatePath());
            SamlUtils.validateSignature(samlResponse, idpCertificate);

            PrivateKey privateKey = resolveServiceProviderKey();
            List<Assertion> assertions = SamlUtils.decryptAssertionsIfNeeded(samlResponse, privateKey);
            String username = SamlUtils.extractSubject(assertions);
            Set<String> roles = extractRoles(assertions);

            establishSecurityContext(clientSubject, username, roles);
            LOGGER.info("SAML authentication succeeded for user {} with roles {}", username, roles);
            return AuthStatus.SUCCESS;
        } catch (SamlProcessingException e) {
            LOGGER.error("SAML processing failed: {}", e.getMessage(), e);
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "SAML validation failed");
            } catch (IOException ioException) {
                throw new AuthException("Unable to send error response", ioException);
            }
            return AuthStatus.SEND_FAILURE;
        }
    }

    private void triggerIdentityProviderRedirect(HttpServletRequest request, HttpServletResponse response) throws AuthException {
        try {
            String relayState = Base64.getEncoder().encodeToString(request.getRequestURL().toString().getBytes(UTF_8));
            String acsUrl = request.getRequestURL().toString();
            LOGGER.info("  AuthnRequest relayState: {}", relayState);
            LOGGER.info("AuthnRequest acsUrl: {}", acsUrl);
            BasicX509Credential credential = loadServiceProviderCredential();
            var authnRequest = SamlUtils.buildAuthnRequest(config.getIdpSsoUrl(), config.getSpEntityId(), acsUrl);
            LOGGER.info("AuthnRequest toString: {}", authnRequest.toString());
            SamlUtils.signAuthnRequest(authnRequest, credential);
            LOGGER.info("AuthnRequest end signAuthnRequest: {}");
            String encodedRequest = SamlUtils.deflateAndBase64Encode(authnRequest);
            LOGGER.info("AuthnRequest encodedRequest: {}", encodedRequest);
            String redirectUrl = config.getIdpSsoUrl()
                    + "?SAMLRequest=" + URLEncoder.encode(encodedRequest, UTF_8)
                    + "&RelayState=" + URLEncoder.encode(relayState, UTF_8);
            LOGGER.debug("Redirecting to IdP with AuthnRequest: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
        } catch (IOException | SamlProcessingException e) {
            throw new AuthException("Unable to redirect to IdP", e);
        }
    }

    private PrivateKey resolveServiceProviderKey() throws SamlProcessingException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (var in = java.nio.file.Files.newInputStream(config.getKeystorePath())) {
                keyStore.load(in, config.getKeystorePassword());
            }
            return (PrivateKey) keyStore.getKey(config.getKeyAlias(), config.getKeyPassword());
        } catch (Exception e) {
            throw new SamlProcessingException("Unable to load SP private key", e);
        }
    }

    private BasicX509Credential loadServiceProviderCredential() throws SamlProcessingException {
        try {
        	 LOGGER.debug("AuthnRequest loadServiceProviderCredential");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (var in = java.nio.file.Files.newInputStream(config.getKeystorePath())) {
                keyStore.load(in, config.getKeystorePassword());
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(config.getKeyAlias(), config.getKeyPassword());
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(config.getKeyAlias());
            if (certificate == null) {
                throw new SamlProcessingException("No certificate found for alias " + config.getKeyAlias());
            }
            return new BasicX509Credential(certificate, privateKey);
        } catch (Exception e) {
        	 LOGGER.debug("AuthnRequest Unable to load SP credentials");
            throw new SamlProcessingException("Unable to load SP credentials", e);
        }
    }

    private Set<String> extractRoles(List<Assertion> assertions) {
        Set<String> roles = new HashSet<>();
        for (Assertion assertion : assertions) {
            for (AttributeStatement statement : assertion.getAttributeStatements()) {
                for (Attribute attribute : statement.getAttributes()) {
                    String name = attribute.getName();
                    if ("roles".equalsIgnoreCase(name) || "role".equalsIgnoreCase(name) ||
                            "groups".equalsIgnoreCase(name)) {
                        attribute.getAttributeValues().forEach(value -> roles.add(value.getDOM().getTextContent()));
                    }
                }
            }
        }
        if (roles.isEmpty()) {
            roles.add("user");
        }
        return roles;
    }

    private void establishSecurityContext(Subject clientSubject, String username, Set<String> roles) throws AuthException {
        CallerPrincipalCallback principalCallback = new CallerPrincipalCallback(clientSubject, username);
        GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, roles.toArray(new String[0]));
        try {
            callbackHandler.handle(new Callback[]{principalCallback, groupCallback});
        } catch (IOException | UnsupportedCallbackException e) {
            throw new AuthException("Unable to propagate security context", e);
        }
    }

    private boolean isLogoutRequest(String path) {
        return "/logout".equals(path) || path.endsWith("/logout");
    }

    private void clearSubject(Subject subject) {
        if (subject != null) {
            subject.getPrincipals().clear();
            subject.getPrivateCredentials().clear();
            subject.getPublicCredentials().clear();
        }
    }

    private String normalizePath(HttpServletRequest request) {
        String contextPath = Optional.ofNullable(request.getContextPath()).orElse("");
        String uri = Optional.ofNullable(request.getRequestURI()).orElse("");
        String path = uri.substring(contextPath.length());
        if (path.isEmpty()) {
            return "/";
        }
        return path;
    }
}
