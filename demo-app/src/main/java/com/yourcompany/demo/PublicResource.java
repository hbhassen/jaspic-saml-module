package com.yourcompany.demo;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Public endpoint that does not require authentication. The path is included
 * in the module's {@code public-paths} to demonstrate that the JASPIC module
 * can bypass security for selected resources.
 */
@Path("/public")
public class PublicResource {

    @GET
    @Path("/hello")
    @Produces(MediaType.APPLICATION_JSON)
    public Response hello() {
        return Response.ok(new Message("Hello from a public endpoint"))
                .build();
    }
}
