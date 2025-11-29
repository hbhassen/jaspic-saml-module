package com.yourcompany.jaspic.saml;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Utility to derive application roles from SAML assertions.
 */
public final class SamlRoleExtractor {

    private SamlRoleExtractor() {
    }

    public static Set<String> extractRoles(List<Assertion> assertions) {
        Set<String> roles = new HashSet<>();
        for (Assertion assertion : assertions) {
            for (AttributeStatement statement : assertion.getAttributeStatements()) {
                for (Attribute attribute : statement.getAttributes()) {
                    String name = attribute.getName();
                    if ("roles".equalsIgnoreCase(name) || "role".equalsIgnoreCase(name)
                            || "groups".equalsIgnoreCase(name) || "Role".equalsIgnoreCase(name)) {
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
}
