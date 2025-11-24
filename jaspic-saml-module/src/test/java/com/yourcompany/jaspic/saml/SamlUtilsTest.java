package com.yourcompany.jaspic.saml;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SamlUtilsTest {

    @Test
    void buildAuthnRequestBuildsCompleteRequest() throws SamlProcessingException {
        String idpSsoUrl = "https://idp.example.com/sso";
        String spEntityId = "urn:yourcompany:sp";
        String acsUrl = "https://sp.example.com/acs";

        AuthnRequest authnRequest = SamlUtils.buildAuthnRequest(idpSsoUrl, spEntityId, acsUrl);

        assertNotNull(authnRequest);
        assertNotNull(authnRequest.getID());
        assertEquals(idpSsoUrl, authnRequest.getDestination());
        assertEquals(acsUrl, authnRequest.getAssertionConsumerServiceURL());
        assertEquals(spEntityId, authnRequest.getIssuer().getValue());
        assertTrue(Boolean.TRUE.equals(authnRequest.getNameIDPolicy().getAllowCreate()));
    }
}
