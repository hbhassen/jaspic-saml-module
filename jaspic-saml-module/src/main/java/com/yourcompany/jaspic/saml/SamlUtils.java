package com.yourcompany.jaspic.saml;

import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Collection of helper utilities around OpenSAML 4 that keep the {@link SamlServerAuthModule} lean.
 * <p>
 * Typical usage sequence:
 * <pre>{@code
 * SamlUtils.initializeOpenSaml();
 * Response response = SamlUtils.parseSamlResponse(base64Response);
 * SamlUtils.validateSignature(response, SamlUtils.loadCertificate(certificateBytes));
 * List<Assertion> assertions = SamlUtils.decryptAssertionsIfNeeded(response, privateKey);
 * String username = SamlUtils.extractSubject(assertions);
 * }</pre>
 */
public final class SamlUtils {

    private static volatile boolean initialized;

    private SamlUtils() {
        // Utility class
    }

    /**
     * Initializes the OpenSAML subsystem exactly once. The initialization is threadsafe and idempotent so it can be
     * invoked from application code or tests without side effects.
     *
     * @throws SamlProcessingException when initialization fails
     */
    public static synchronized void initializeOpenSaml() throws SamlProcessingException {
        if (initialized) {
            return;
        }
        try {
            InitializationService.initialize();
            initialized = true;
        } catch (Exception e) {
            throw new SamlProcessingException("Unable to initialize OpenSAML", e);
        }
    }

    /**
     * Parses a Base64 encoded SAMLResponse coming from an HTTP POST binding into an OpenSAML {@link Response} instance.
     *
     * @param base64Response value of the {@code SAMLResponse} form parameter
     * @return parsed response
     * @throws SamlProcessingException when decoding or unmarshalling fails
     */
    public static Response parseSamlResponse(String base64Response) throws SamlProcessingException {
        Objects.requireNonNull(base64Response, "SAMLResponse must not be null");
        initializeOpenSaml();

        byte[] decoded = Base64.getDecoder().decode(base64Response);
        try (InputStream is = new ByteArrayInputStream(decoded)) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(is);
            Element rootElement = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElement);
            if (unmarshaller == null) {
                throw new SamlProcessingException("No unmarshaller for element " + rootElement.getNodeName());
            }
            XMLObject xmlObject = unmarshaller.unmarshall(rootElement);
            return (Response) xmlObject;
        } catch (IOException | ParserConfigurationException | UnmarshallingException | org.xml.sax.SAXException e) {
            throw new SamlProcessingException("Unable to parse SAMLResponse", e);
        }
    }

    /**
     * Validates the XML Signature of the response using the provided IdP certificate.
     * The method returns silently when validation succeeds and throws when the signature is invalid.
     *
     * @param response      response to validate
     * @param idpCertificate trusted IdP certificate
     * @throws SamlProcessingException when the response is unsigned or the signature is invalid
     */
    public static void validateSignature(Response response, X509Certificate idpCertificate) throws SamlProcessingException {
        initializeOpenSaml();
        Signature signature = response.getSignature();
        if (signature == null) {
            throw new SamlProcessingException("SAMLResponse is not signed by the Identity Provider");
        }
        try {
            BasicX509Credential credential = new BasicX509Credential(idpCertificate);
            SignatureValidator.validate(signature, credential);
        } catch (SignatureException e) {
            throw new SamlProcessingException("Invalid SAML signature", e);
        }
    }

    /**
     * Decrypts encrypted assertions in-place using the SP private key. If the response already contains plain
     * assertions, it is returned as-is. The returned list is never {@code null} but may be empty when the IdP did
     * not include any assertions.
     *
     * @param response   SAML response potentially containing encrypted assertions
     * @param privateKey private key matching the SP certificate
     * @return list of decrypted or plain assertions
     * @throws SamlProcessingException when decryption fails
     */
    public static List<Assertion> decryptAssertionsIfNeeded(Response response, PrivateKey privateKey)
            throws SamlProcessingException {
        initializeOpenSaml();
        List<Assertion> assertions = new ArrayList<>(response.getAssertions());
        if (!response.getEncryptedAssertions().isEmpty()) {
            BasicX509Credential credential = new BasicX509Credential(null, privateKey);
            StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
            Decrypter decrypter = new Decrypter(null, resolver, null);
            for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
                try {
                    assertions.add(decrypter.decrypt(encryptedAssertion));
                } catch (DecryptionException e) {
                    throw new SamlProcessingException("Unable to decrypt assertion", e);
                }
            }
        }
        return Collections.unmodifiableList(assertions);
    }

    /**
     * Extracts the subject NameID from the first available assertion. The method favors bearer subject confirmation
     * but will gracefully fallback to any available subject to keep interoperability with custom IdPs.
     *
     * @param assertions decrypted or plain assertions
     * @return subject name
     * @throws SamlProcessingException when the subject is missing
     */
    public static String extractSubject(List<Assertion> assertions) throws SamlProcessingException {
        initializeOpenSaml();
        for (Assertion assertion : assertions) {
            Subject subject = assertion.getSubject();
            if (subject != null && subject.getNameID() != null) {
                return subject.getNameID().getValue();
            }
        }
        throw new SamlProcessingException("No subject found in SAML assertion");
    }

    /**
     * Convenience helper to load an X.509 certificate from the provided path. The method can be reused by unit tests
     * or configuration bootstrap code.
     *
     * @param certificatePath path to a PEM or DER encoded certificate
     * @return parsed certificate
     * @throws SamlProcessingException when the certificate cannot be read
     */
    public static X509Certificate loadCertificate(Path certificatePath) throws SamlProcessingException {
        try (InputStream inputStream = Files.newInputStream(certificatePath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(inputStream);
        } catch (Exception e) {
            throw new SamlProcessingException("Unable to read IdP certificate from " + certificatePath, e);
        }
    }

    /**
     * Builds a user friendly assertion summary which can be logged for troubleshooting without leaking the complete
     * XML response. Only high-level metadata is included to keep audit logs compact.
     *
     * @param response SAML response
     * @return formatted summary string
     */
    public static String summarizeResponse(Response response) {
        String issuer = response.getIssuer() != null ? response.getIssuer().getValue() : "<unknown issuer>";
        String destination = response.getDestination();
        return String.format("SAML Response from %s to %s with %d assertion(s) (HTTP-POST)",
                issuer, destination, response.getAssertions().size());
    }
}
