package com.yourcompany.jaspic.saml;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.ServletInfo;
import jakarta.servlet.ServletContext;

/**
 * Extension Undertow qui enregistre la servlet ACS pour chaque déploiement.
 */
public class SamlServletExtension implements ServletExtension {

    public static final String SERVLET_NAME = "SamlAcsServlet";
    public static final String SERVLET_MAPPING = "/login/saml2/sso/login";

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        org.slf4j.LoggerFactory.getLogger(SamlServletExtension.class)
                .info("Entrée handleDeployment - enregistrement de la servlet ACS");
        ServletInfo servletInfo = new ServletInfo(SERVLET_NAME, SamlAcsServlet.class)
                .addMapping(SERVLET_MAPPING)
                .setLoadOnStartup(1)
                .setAsyncSupported(false);
        deploymentInfo.addServlet(servletInfo);
        org.slf4j.LoggerFactory.getLogger(SamlServletExtension.class)
                .info("Sortie handleDeployment - servlet ACS enregistrée");
    }
}
