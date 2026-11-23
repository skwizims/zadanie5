package zadanie1.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final long accessSeconds;
    private final long refreshSeconds;

    public JwtService(
            @Value("${app.jwt.secret-hex}") String secretHex,
            @Value("${app.jwt.access-seconds:900}") long accessSeconds,
            @Value("${app.jwt.refresh-seconds:604800}") long refreshSeconds
    ) {
        this.key = Keys.hmacShaKeyFor(HexFormat.of().parseHex(secretHex));
        this.accessSeconds = accessSeconds;
        this.refreshSeconds = refreshSeconds;
    }

    public record Issued(String token, Instant expiry) {
    }

    public Issued createAccess(String username) {
        return create(username, "access", accessSeconds);
    }

    public Issued createRefresh(String username) {
        return create(username, "refresh", refreshSeconds);
    }

    private Issued create(String username, String type, long lifetimeSeconds) {
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiry = issuedAt.plusSeconds(lifetimeSeconds);

        String token = Jwts.builder()
                .subject(username)
                .id(UUID.randomUUID().toString())
                .claim("type", type)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiry))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

        return new Issued(token, expiry);
    }

    public Claims validate(String token, String expectedType) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        if (claims.getSubject() == null
                || claims.getId() == null
                || !expectedType.equals(claims.get("type", String.class))) {
            throw new JwtException("Invalid token type or claims");
        }

        return claims;
    }

    public long getAccessSeconds() {
        return accessSeconds;
    }

    public long getRefreshSeconds() {
        return refreshSeconds;
    }
}
