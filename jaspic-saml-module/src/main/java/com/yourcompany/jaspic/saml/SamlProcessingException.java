package com.yourcompany.jaspic.saml;

/**
 * Exception raised when a SAML message cannot be parsed, validated or decrypted.
 * The class is deliberately checked to force callers to deal with error handling
 * explicitly rather than quietly ignoring validation issues.
 */
public class SamlProcessingException extends Exception {

    /**
     * Creates a new instance with a descriptive message.
     *
     * @param message human readable error description
     */
    public SamlProcessingException(String message) {
        super(message);
    }

    /**
     * Creates a new instance with a descriptive message and root cause.
     *
     * @param message human readable error description
     * @param cause   underlying cause that triggered the failure
     */
    public SamlProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
}
