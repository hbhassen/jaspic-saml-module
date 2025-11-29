package com.yourcompany.jaspic.saml;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.config.XMLObjectProviderInitializer;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.config.impl.SAMLConfigurationInitializer;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.provider.ApacheSantuarioSignerProviderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

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
    private static final Logger LOGGER = LoggerFactory.getLogger(SamlUtils.class);

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
    public static void initializeOpenSaml() throws SamlProcessingException {
        if (initialized) {
            return;
        }

        synchronized (SamlUtils.class) {
            if (initialized) {
                return;
            }

            ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
            ClassLoader samlClassLoader = SamlUtils.class.getClassLoader();
            try {
                // Ensure OpenSAML can discover its configuration resources even when running inside a WildFly module.
                Thread.currentThread().setContextClassLoader(samlClassLoader);

                InitializationService.initialize();

                XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
                // In some modular containers (WildFly/JBoss Modules) the ServiceLoader discovery used by the
                // InitializationService may fail to wire the registry, so attempt a manual bootstrap as a fallback.
                if (registry == null || registry.getBuilderFactory() == null) {
                    try {
                        new XMLObjectProviderInitializer().init();
                        registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
                    } catch (InitializationException e) {
                        throw new SamlProcessingException("OpenSAML fallback initialization failed", e);
                    }
                }

                if (registry == null || registry.getBuilderFactory() == null) {
                    throw new SamlProcessingException("OpenSAML initialization failed: builder factory not available");
                }
                // Ensure the registry is bound for subsequent lookups performed with the application classloader.
                ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

                if (XMLObjectProviderRegistrySupport.getParserPool() == null) {
                    try {
                        BasicParserPool parserPool = new BasicParserPool();
                        parserPool.setMaxPoolSize(50);
                        parserPool.setNamespaceAware(true);
                        parserPool.initialize();
                        // Bind parser pool both on the static support and on the registry to avoid null marshaller issues.
                        XMLObjectProviderRegistrySupport.setParserPool(parserPool);
                        registry.setParserPool(parserPool);
                    } catch (ComponentInitializationException e) {
                        throw new SamlProcessingException("OpenSAML initialization failed: unable to initialize parser pool", e);
                    }
                }

                var builderFactory = registry.getBuilderFactory();
                if (builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME) == null) {
                    try {
                        // Explicitly initialize SAML object providers/config when ServiceLoader discovery is blocked.
                        new org.opensaml.saml.config.impl.XMLObjectProviderInitializer().init();
                        new SAMLConfigurationInitializer().init();
                        new org.opensaml.xmlsec.config.impl.XMLObjectProviderInitializer().init();
                        new JavaCryptoValidationInitializer().init();
                        registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
                        builderFactory = registry != null ? registry.getBuilderFactory() : null;
                    } catch (InitializationException e) {
                        throw new SamlProcessingException("OpenSAML SAML initializer failed", e);
                    }
                }
                if (builderFactory == null || builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME) == null) {
                    throw new SamlProcessingException("OpenSAML initialization failed: AuthnRequest builder unavailable");
                }
                if (builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME) == null) {
                    throw new SamlProcessingException("OpenSAML initialization failed: Signature builder unavailable");
                }
                initialized = true;
            } catch (InitializationException e) {
                throw new SamlProcessingException("Unable to initialize OpenSAML", e);
            } finally {
                Thread.currentThread().setContextClassLoader(originalClassLoader);
            }
        }
    }

    private static String generateUniqueId() {
        return "_" + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Builds a basic AuthnRequest suitable for HTTP-Redirect binding.
     */
    public static AuthnRequest buildAuthnRequest(String idpSsoUrl, String spEntityId, String acsUrl)
            throws SamlProcessingException {
        initializeOpenSaml();
        if (idpSsoUrl == null || idpSsoUrl.isBlank()) {
            throw new SamlProcessingException("IdP SSO URL must not be blank");
        }
        if (spEntityId == null || spEntityId.isBlank()) {
            throw new SamlProcessingException("SP entity ID must not be blank");
        }
        if (acsUrl == null || acsUrl.isBlank()) {
            throw new SamlProcessingException("ACS URL must not be blank");
        }
        try {
            var builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            if (builderFactory == null) {
                throw new SamlProcessingException("OpenSAML was not initialized: builder factory is unavailable");
            }

            @SuppressWarnings("unchecked")
            XMLObjectBuilder<AuthnRequest> authnRequestBuilder =
                    (XMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
            if (authnRequestBuilder == null) {
                throw new SamlProcessingException("No builder registered for AuthnRequest");
            }

            LOGGER.info("buildAuthnRequest for IdP {} and SP {}", idpSsoUrl, spEntityId);
            AuthnRequest authnRequest = authnRequestBuilder.buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
            authnRequest.setID(generateUniqueId());
            authnRequest.setIssueInstant(Instant.now());
            authnRequest.setDestination(idpSsoUrl);
            authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(acsUrl);
            authnRequest.setVersion(SAMLVersion.VERSION_20);

            Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
            issuer.setValue(spEntityId);
            authnRequest.setIssuer(issuer);

            NameIDPolicy nameIDPolicy = (NameIDPolicy) XMLObjectSupport.buildXMLObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
            nameIDPolicy.setAllowCreate(true);
            authnRequest.setNameIDPolicy(nameIDPolicy);

            return authnRequest;
        } catch (Exception e) {
            LOGGER.error("Unable to build AuthnRequest", e);
            throw new SamlProcessingException("Unable to build AuthnRequest", e);
        }
    }

    /**
     * Signs the provided AuthnRequest using RSA SHA-256 and exclusive canonicalization.
     */
    public static void signAuthnRequest(AuthnRequest authnRequest, X509Credential credential)
            throws SamlProcessingException {
        initializeOpenSaml();
        LOGGER.debug("Signing AuthnRequest {}", authnRequest.getID());
        Objects.requireNonNull(authnRequest, "AuthnRequest must not be null");
        Objects.requireNonNull(credential, "Signing credential must not be null");

        try {
            Signature signature = (Signature) XMLObjectSupport.buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(credential);
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            // Explicitly attach content reference with a digest algorithm to avoid provider lookup failures.
            var contentReference = new SAMLObjectContentReference(authnRequest);
            contentReference.setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA256);
            signature.getContentReferences().clear();
            signature.getContentReferences().add(contentReference);

            X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
            signature.setKeyInfo(keyInfoGenerator.generate(credential));
            authnRequest.setSignature(signature);
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);
            if (marshaller == null) {
                throw new SamlProcessingException("No marshaller available for AuthnRequest");
            }
            marshaller.marshall(authnRequest);
            new ApacheSantuarioSignerProviderImpl().signObject(signature);
        } catch (Exception e) {
            LOGGER.error("Unable to sign AuthnRequest: {}", e.getMessage(), e);
            throw new SamlProcessingException("Unable to sign AuthnRequest", e);
        }
    }

    /**
     * Marshals, deflates and Base64 encodes a SAML object ready for HTTP-Redirect transport.
     */
    public static String deflateAndBase64Encode(XMLObject xmlObject) throws SamlProcessingException {
        initializeOpenSaml();
        try {
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject);
            if (marshaller == null) {
                throw new SamlProcessingException("No marshaller for object " + xmlObject.getElementQName());
            }
            Element element = marshaller.marshall(xmlObject);
            String xmlString = SerializeSupport.nodeToString(element);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (DeflaterOutputStream deflaterOutputStream =
                         new DeflaterOutputStream(byteArrayOutputStream, new Deflater(Deflater.DEFLATED, true))) {
                deflaterOutputStream.write(xmlString.getBytes(UTF_8));
            }
            return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        } catch (MarshallingException | IOException e) {
            throw new SamlProcessingException("Unable to encode SAML object", e);
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
