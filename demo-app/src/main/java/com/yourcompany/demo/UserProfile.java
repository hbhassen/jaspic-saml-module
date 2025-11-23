package com.yourcompany.demo;

import java.util.Collections;
import java.util.Set;

/**
 * DTO returned by the secure endpoint. It exposes the authenticated username
 * and roles reported by the container so clients can verify that the SAML
 * assertion has been correctly mapped to groups.
 */
public class UserProfile {
    private String username;
    private Set<String> roles;

    public UserProfile() {
    }

    public UserProfile(String username, Set<String> roles) {
        this.username = username;
        this.roles = Collections.unmodifiableSet(roles);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = Collections.unmodifiableSet(roles);
    }
}
