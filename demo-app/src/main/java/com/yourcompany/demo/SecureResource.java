package com.yourcompany.demo;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import java.util.Set;
import java.util.TreeSet;

/**
 * Protected endpoint that relies on the JASPIC module to populate the caller
 * {@link java.security.Principal} and role set. Access requires that the user
 * is authenticated by the SAML Identity Provider.
 */
@Path("/secure")
public class SecureResource {

    @GET
    @Path("/profile")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed({"user", "admin"})
    public Response profile(@Context SecurityContext securityContext) {
        String username = securityContext.getUserPrincipal() != null
                ? securityContext.getUserPrincipal().getName()
                : "anonymous";

        Set<String> roles = new TreeSet<>();
        for (String candidate : new String[]{"admin", "user"}) {
            if (securityContext.isUserInRole(candidate)) {
                roles.add(candidate);
            }
        }

        return Response.ok(new UserProfile(username, roles)).build();
    }
}
