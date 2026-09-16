package com.e2eecb.server;

import com.e2eecb.crypto.PreKeyBundle;

import java.util.HashMap;
import java.util.Map;

public class InMemoryDirectory {

    private final Map<String, PreKeyBundle> bundles = new HashMap<>();

    public void publish(PreKeyBundle bundle) {
        bundles.put(bundle.userId, bundle);
    }

    public PreKeyBundle fetch(String userId) {
        PreKeyBundle bundle = bundles.get(userId);
        if (bundle == null) {
            throw new IllegalStateException("No bundle for " + userId);
        }
        return bundle;
    }
}
