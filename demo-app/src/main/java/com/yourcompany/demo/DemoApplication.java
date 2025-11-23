package com.yourcompany.demo;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

/**
 * JAX-RS activator that registers REST endpoints under the application root.
 * The class is intentionally minimal because authentication is enforced by the
 * container through the JASPIC module, not by application code.
 */
@ApplicationPath("/")
public class DemoApplication extends Application {
    // No custom configuration required
}
