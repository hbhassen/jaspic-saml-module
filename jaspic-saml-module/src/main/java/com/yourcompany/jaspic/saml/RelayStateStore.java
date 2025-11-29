package com.yourcompany.jaspic.saml;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store that maps a RelayState to the original requested URL.
 * <p>
 * This keeps the flow stateless for the client while allowing the ACS servlet to recover
 * the target URL to which the browser should be redirected after a successful SAML login.
 */
public final class RelayStateStore {

    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);
    private static final RelayStateStore INSTANCE = new RelayStateStore();

    private final Map<String, Entry> store = new ConcurrentHashMap<>();

    private RelayStateStore() {
    }

    /**
     * @return singleton instance
     */
    public static RelayStateStore getInstance() {
        return INSTANCE;
    }

    /**
     * Stores the original URL and returns the generated RelayState identifier.
     *
     * @param originalUrl URL to restore after SAML login
     * @return relay state token
     */
    public String put(String originalUrl) {
        String relayState = UUID.randomUUID().toString();
        store.put(relayState, new Entry(originalUrl, Instant.now().plus(DEFAULT_TTL)));
        return relayState;
    }

    /**
     * Retrieves and removes the original URL for a relay state.
     *
     * @param relayState relay state token
     * @return original URL or null if missing/expired
     */
    public String consume(String relayState) {
        if (relayState == null) {
            return null;
        }
        Entry entry = store.remove(relayState);
        if (entry == null) {
            return null;
        }
        if (entry.expiresAt.isBefore(Instant.now())) {
            return null;
        }
        return entry.originalUrl;
    }

    private record Entry(String originalUrl, Instant expiresAt) {
    }
}
