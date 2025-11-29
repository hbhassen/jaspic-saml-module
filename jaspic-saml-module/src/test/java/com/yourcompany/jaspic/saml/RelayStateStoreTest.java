package com.yourcompany.jaspic.saml;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RelayStateStoreTest {

    @Test
    void storesAndConsumesRelayState() {
        RelayStateStore store = RelayStateStore.getInstance();
        String relay = store.put("http://localhost/demo-app/secure");
        assertNotNull(relay);
        String restored = store.consume(relay);
        assertEquals("http://localhost/demo-app/secure", restored);
        assertNull(store.consume(relay));
    }
}
