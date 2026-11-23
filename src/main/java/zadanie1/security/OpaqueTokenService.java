package zadanie1.security;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class OpaqueTokenService {

    private final SecureRandom random = new SecureRandom();

    public String generate() {
        byte[] tokenBytes = new byte[32];
        random.nextBytes(tokenBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(tokenBytes);
    }
}
