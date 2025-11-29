package com.yourcompany.jaspic.saml;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * Servlet ACS (Assertion Consumer Service) qui traite les SAMLResponse POSTées par l'IdP.
 * <p>
 * Enregistrée automatiquement via Undertow {@link SamlServletExtension}; aucun WAR ou web.xml n'est requis.
 */
public class SamlAcsServlet extends HttpServlet {

    public static final String SESSION_PRINCIPAL = "saml.auth.principal";
    public static final String SESSION_ROLES = "saml.auth.roles";

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(SamlAcsServlet.class);

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        LOGGER.info("Entrée SamlAcsServlet.doPost");
        String samlResponseParam = req.getParameter("SAMLResponse");
        String relayState = req.getParameter("RelayState");

        if (samlResponseParam == null || samlResponseParam.isBlank() || relayState == null || relayState.isBlank()) {
            LOGGER.info("Paramètres SAMLResponse ou RelayState manquants");
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "SAMLResponse ou RelayState manquant");
            return;
        }

        try {
            SamlJaspicConfig config = SamlJaspicConfig.from((java.util.Map) System.getProperties());

            // Analyse et validation de la réponse.
            Response samlResponse = SamlUtils.parseSamlResponse(samlResponseParam);
            X509Certificate idpCertificate = SamlUtils.loadCertificate(config.getIdpCertificatePath());
            SamlUtils.validateSignature(samlResponse, idpCertificate);

            // Déchiffre si nécessaire et extrait l'utilisateur/les rôles.
            PrivateKey privateKey = resolveServiceProviderKey(config);
            List<Assertion> assertions = SamlUtils.decryptAssertionsIfNeeded(samlResponse, privateKey);
            String username = SamlUtils.extractSubject(assertions);
            Set<String> roles = SamlRoleExtractor.extractRoles(assertions);

            // Marque la session comme authentifiée.
            HttpSession session = req.getSession(true);
            session.setAttribute(SESSION_PRINCIPAL, username);
            session.setAttribute(SESSION_ROLES, roles);

            // Restaure l'URL initiale via le relay state et redirige.
            String originalUrl = RelayStateStore.getInstance().consume(relayState);
            if (originalUrl == null || originalUrl.isBlank()) {
                originalUrl = "/demo-app/secure";
            }
            resp.sendRedirect(originalUrl);
        } catch (SamlProcessingException e) {
            LOGGER.error("SAMLResponse invalide : {}", e.getMessage(), e);
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "SAMLResponse invalide : " + e.getMessage());
        }
        LOGGER.info("Sortie SamlAcsServlet.doPost");
    }

    private PrivateKey resolveServiceProviderKey(SamlJaspicConfig config) throws SamlProcessingException {
        LOGGER.info("Entrée resolveServiceProviderKey");
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (var in = java.nio.file.Files.newInputStream(config.getKeystorePath())) {
                keyStore.load(in, config.getKeystorePassword());
            }
            return (PrivateKey) keyStore.getKey(config.getKeyAlias(), config.getKeyPassword());
        } catch (Exception e) {
            throw new SamlProcessingException("Impossible de charger la clé privée du SP", e);
        } finally {
            LOGGER.info("Sortie resolveServiceProviderKey");
        }
    }
}
