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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.opensaml.security.x509.BasicX509Credential;
import com.yourcompany.jaspic.saml.RelayStateStore;
import com.yourcompany.jaspic.saml.SamlAcsServlet;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * {@link ServerAuthModule} qui délègue l'authentification à un fournisseur SAML v2 externe.
 * <p>Comportement :</p>
 * <ul>
 *     <li>Ignore l'authentification sur les chemins publics configurés via {@link SamlJaspicConfig}.</li>
 *     <li>Quand une {@code SAMLResponse} est postée, elle est parsée, la signature est validée et les assertions sont déchiffrées
 *     avant de créer un {@link Principal} et des rôles sur le subject appelant.</li>
 *     <li>Quand l'authentification est requise sans assertion présente, l'utilisateur est redirigé vers l'IdP.</li>
 *     <li>Supporte le logout simple en vidant le subject sur {@code /logout}.</li>
 * </ul>
 */
public class SamlServerAuthModule implements ServerAuthModule {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlServerAuthModule.class);
    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[]{HttpServletRequest.class, HttpServletResponse.class};

    private CallbackHandler callbackHandler;
    private SamlJaspicConfig config;

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        LOGGER.info("Entrée initialize");
        this.callbackHandler = Objects.requireNonNull(handler, "CallbackHandler is required");
        this.config = SamlJaspicConfig.from(options);

        try {
            SamlUtils.initializeOpenSaml();
            List<String> warnings = config.validatePaths();
            warnings.forEach(message -> LOGGER.warn("Avertissement de configuration : {}", message));
            LOGGER.info("Module SAML JASPIC initialisé avec l'entityId SP {}", config.getSpEntityId());
        } catch (SamlProcessingException e) {
            throw new AuthException("Failed to initialize OpenSAML: " + e.getMessage());
        }
        LOGGER.info("Sortie initialize");
    }

    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES.clone();
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        LOGGER.info("Entrée validateRequest");
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
        String path = normalizePath(request);

        if (config.isPublicPath(path)) {
            LOGGER.debug("Chemin public détecté, authentification SAML ignorée : {}", path);
            LOGGER.info("Sortie validateRequest (chemin public)");
            return AuthStatus.SUCCESS;
        }

        // Lightweight logout handling keeps the interaction stateless.
        if (isLogoutRequest(path)) {
            clearSubject(clientSubject);
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            LOGGER.info("Sortie validateRequest (logout)");
            return AuthStatus.SEND_SUCCESS;
        }

        // If the ACS servlet already established a session principal, reuse it.
        SessionPrincipal sessionPrincipal = getSessionPrincipal(request);
        if (sessionPrincipal != null) {
            establishSecurityContext(clientSubject, sessionPrincipal.username(), sessionPrincipal.roles());
            LOGGER.info("Sortie validateRequest (session existante)");
            return AuthStatus.SUCCESS;
        }

        String samlResponseParam = request.getParameter("SAMLResponse");
        if (samlResponseParam != null && !samlResponseParam.isBlank()) {
            return handleSamlResponse(clientSubject, response, samlResponseParam);
        }
        LOGGER.info("Authentification requise pour le chemin {}", path);
        // Aucune assertion présente : on déclenche la redirection vers l'IdP.
        triggerIdentityProviderRedirect(request, response);
        LOGGER.info("Sortie validateRequest (redirection IdP)");
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
        LOGGER.info("Entree handleSamlResponse");
        try {
            Response samlResponse = SamlUtils.parseSamlResponse(samlResponseParam);
            X509Certificate idpCertificate = SamlUtils.loadCertificate(config.getIdpCertificatePath());
            SamlUtils.validateSignature(samlResponse, idpCertificate);

            PrivateKey privateKey = resolveServiceProviderKey();
            List<Assertion> assertions = SamlUtils.decryptAssertionsIfNeeded(samlResponse, privateKey);
            String username = SamlUtils.extractSubject(assertions);
            Set<String> roles = extractRoles(assertions);

            establishSecurityContext(clientSubject, username, roles);
            LOGGER.info("Authentification SAML reussie pour l'utilisateur {} avec roles {}", username, roles);
            LOGGER.info("Sortie handleSamlResponse (succes)");
            return AuthStatus.SUCCESS;
        } catch (SamlProcessingException e) {
            LOGGER.error("Echec du traitement SAML : {}", e.getMessage(), e);
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Validation SAML echouee");
            } catch (IOException ioException) {
                throw new AuthException("Impossible d'envoyer la reponse d'erreur", ioException);
            }
            LOGGER.info("Sortie handleSamlResponse (echec)");
            return AuthStatus.SEND_FAILURE;
        }
    }

    private void triggerIdentityProviderRedirect(HttpServletRequest request, HttpServletResponse response) throws AuthException {
        LOGGER.info("Entrée triggerIdentityProviderRedirect");
        try {
            String originalUrl = buildFullRequestUrl(request);
            String relayState = RelayStateStore.getInstance().put(originalUrl);
            String acsUrl = "http://localhost:8080/demo-app/login/saml2/sso/login";
            LOGGER.info("  AuthnRequest relayState : {}", relayState);
            LOGGER.info("AuthnRequest ACS : {}", acsUrl);
            BasicX509Credential credential = loadServiceProviderCredential();
            var authnRequest = SamlUtils.buildAuthnRequest(config.getIdpSsoUrl(), config.getSpEntityId(), acsUrl);
            LOGGER.info("AuthnRequest contenu : {}", authnRequest.toString());
            SamlUtils.signAuthnRequest(authnRequest, credential);
            LOGGER.info("AuthnRequest end signAuthnRequest: {}");
            String encodedRequest = SamlUtils.deflateAndBase64Encode(authnRequest);
            LOGGER.info("AuthnRequest encodée : {}", encodedRequest);
            String redirectUrl = config.getIdpSsoUrl()
                    + "?SAMLRequest=" + URLEncoder.encode(encodedRequest, UTF_8)
                    + "&RelayState=" + URLEncoder.encode(relayState, UTF_8);
            LOGGER.info("Redirection vers IdP avec AuthnRequest: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
        } catch (IOException | SamlProcessingException e) {
            throw new AuthException("Unable to redirect to IdP", e);
        } finally {
            LOGGER.info("Sortie triggerIdentityProviderRedirect");
        }
    }

    private PrivateKey resolveServiceProviderKey() throws SamlProcessingException {
        LOGGER.info("Entrée resolveServiceProviderKey");
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (var in = java.nio.file.Files.newInputStream(config.getKeystorePath())) {
                keyStore.load(in, config.getKeystorePassword());
            }
            return (PrivateKey) keyStore.getKey(config.getKeyAlias(), config.getKeyPassword());
        } catch (Exception e) {
            throw new SamlProcessingException("Impossible de charger la clé privée SP", e);
        } finally {
            LOGGER.info("Sortie resolveServiceProviderKey");
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
        } finally {
            LOGGER.info("Sortie loadServiceProviderCredential");
        }
    }

    private Set<String> extractRoles(List<Assertion> assertions) {
        LOGGER.info("Entrée extractRoles");
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
        LOGGER.info("Sortie extractRoles avec rôles {}", roles);
        return roles;
    }

    private void establishSecurityContext(Subject clientSubject, String username, Set<String> roles) throws AuthException {
        LOGGER.info("Entrée establishSecurityContext pour {}", username);
        CallerPrincipalCallback principalCallback = new CallerPrincipalCallback(clientSubject, username);
        GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, roles.toArray(new String[0]));
        try {
            callbackHandler.handle(new Callback[]{principalCallback, groupCallback});
        } catch (IOException | UnsupportedCallbackException e) {
            throw new AuthException("Unable to propagate security context", e);
        } finally {
            LOGGER.info("Sortie establishSecurityContext pour {}", username);
        }
    }

    private boolean isLogoutRequest(String path) {
        return "/logout".equals(path) || path.endsWith("/logout");
    }

    private void clearSubject(Subject subject) {
        LOGGER.info("Entrée clearSubject");
        if (subject != null) {
            subject.getPrincipals().clear();
            subject.getPrivateCredentials().clear();
            subject.getPublicCredentials().clear();
        }
        LOGGER.info("Sortie clearSubject");
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

    private SessionPrincipal getSessionPrincipal(HttpServletRequest request) {
        LOGGER.info("Entrée getSessionPrincipal");
        var session = request.getSession(false);
        if (session == null) {
            LOGGER.info("Sortie getSessionPrincipal (aucune session)");
            return null;
        }
        Object user = session.getAttribute(SamlAcsServlet.SESSION_PRINCIPAL);
        Object roles = session.getAttribute(SamlAcsServlet.SESSION_ROLES);
        if (user instanceof String username && roles instanceof Set<?> roleSet) {
            @SuppressWarnings("unchecked")
            Set<String> castRoles = (Set<String>) roleSet;
            LOGGER.info("Sortie getSessionPrincipal (session trouvée pour {})", username);
            return new SessionPrincipal(username, castRoles);
        }
        LOGGER.info("Sortie getSessionPrincipal (données manquantes)");
        return null;
    }

    private String buildAcsUrl(HttpServletRequest request) {
        LOGGER.info("Entrée buildAcsUrl");
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        String contextPath = Optional.ofNullable(request.getContextPath()).orElse("");
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(host);
        if (!("http".equalsIgnoreCase(scheme) && port == 80) && !("https".equalsIgnoreCase(scheme) && port == 443)) {
            sb.append(":").append(port);
        }
        sb.append(contextPath).append("/login/saml2/sso/login");
        String acs = sb.toString();
        LOGGER.info("Sortie buildAcsUrl -> {}", acs);
        return acs;
    }

    private String buildFullRequestUrl(HttpServletRequest request) {
        LOGGER.info("Entrée buildFullRequestUrl");
        StringBuilder sb = new StringBuilder(request.getRequestURL());
        if (request.getQueryString() != null) {
            sb.append('?').append(request.getQueryString());
        }
        String full = sb.toString();
        LOGGER.info("Sortie buildFullRequestUrl -> {}", full);
        return full;
    }

    private record SessionPrincipal(String username, Set<String> roles) {
    }
}
