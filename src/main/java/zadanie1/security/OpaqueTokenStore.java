package zadanie1.security;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OpaqueTokenStore {

    public record Entry(String username, Instant expiry, String type) {
    }

    private final ConcurrentHashMap<String, Entry> values = new ConcurrentHashMap<>();

    public void put(String token, Entry entry) {
        values.put(token, entry);
    }

    public Entry getValid(String token, String type) {
        Entry entry = values.get(token);

        if (entry == null
                || !entry.expiry().isAfter(Instant.now())
                || !entry.type().equals(type)) {
            return null;
        }

        return entry;
    }

    public void revoke(String token) {
        values.remove(token);
    }

    public int size() {
        return values.size();
    }
}
