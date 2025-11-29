package com.yourcompany.jaspic.saml;

import io.undertow.servlet.api.DeploymentInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SamlServletExtensionTest {

    @Test
    void registersAcsServletMapping() {
        DeploymentInfo info = new DeploymentInfo();
        SamlServletExtension extension = new SamlServletExtension();

        extension.handleDeployment(info, null);

        assertTrue(info.getServlets().containsKey(SamlServletExtension.SERVLET_NAME));
        assertTrue(info.getServlets().get(SamlServletExtension.SERVLET_NAME)
                .getMappings().contains(SamlServletExtension.SERVLET_MAPPING));
    }
}
