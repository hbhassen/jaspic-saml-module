package com.yourcompany.demo;

/**
 * Simple DTO used by the demo endpoints. Keeping the payload minimal makes it
 * easy to verify responses with a browser or curl.
 */
public class Message {
    private String message;

    public Message() {
    }

    public Message(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
