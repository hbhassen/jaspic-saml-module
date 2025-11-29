package com.yourcompany.jaspic.saml;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.*;

class SamlAcsServletTest {

    @Test
    void returnsBadRequestWhenMissingParams() throws Exception {
        SamlAcsServlet servlet = new SamlAcsServlet();
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        when(req.getParameter("SAMLResponse")).thenReturn(null);
        when(req.getParameter("RelayState")).thenReturn(null);

        servlet.doPost(req, resp);

        verify(resp).sendError(HttpServletResponse.SC_BAD_REQUEST, "SAMLResponse ou RelayState manquant");
    }
}
