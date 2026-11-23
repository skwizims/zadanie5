package zadanie1.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import zadanie1.model.SessionStatus;
import zadanie1.model.User;
import zadanie1.model.UserSession;
import zadanie1.repository.UserRepository;
import zadanie1.repository.UserSessionRepository;
import zadanie1.security.JwtService;

import java.time.Instant;

@Service
public class TokenService {

    private final JwtService jwt;
    private final UserSessionRepository sessions;
    private final UserRepository users;

    public TokenService(
            JwtService jwt,
            UserSessionRepository sessions,
            UserRepository users
    ) {
        this.jwt = jwt;
        this.sessions = sessions;
        this.users = users;
    }

    public record TokenPair(String accessToken, String refreshToken) {
    }

    public record RefreshResult(TokenPair pair, boolean rejected) {
    }

    @Transactional
    public TokenPair issue(String username, String deviceId) {
        User user = users.findByUsername(username)
                .filter(User::isEnabled)
                .orElseThrow(() -> new IllegalArgumentException("User unavailable"));

        return createAndSave(user.getUsername(), deviceId);
    }

    @Transactional
    public TokenPair register(
            String username,
            String rawPassword,
            String fullName,
            String email,
            String phone,
            String deviceId,
            AuthService auth
    ) {
        User created = auth.register(username, rawPassword, fullName, email, phone);
        return createAndSave(created.getUsername(), deviceId);
    }

    private TokenPair createAndSave(String username, String deviceId) {
        JwtService.Issued access = jwt.createAccess(username);
        JwtService.Issued refresh = jwt.createRefresh(username);

        UserSession session = new UserSession();
        session.setUsername(username);
        session.setDeviceId(deviceId);
        session.setAccessToken(access.token());
        session.setRefreshToken(refresh.token());
        session.setAccessTokenExpiry(access.expiry());
        session.setRefreshTokenExpiry(refresh.expiry());
        session.setStatus(SessionStatus.ACTIVE);

        sessions.save(session);

        return new TokenPair(access.token(), refresh.token());
    }

    @Transactional
    public RefreshResult refresh(String token) {
        Claims claims;
        try {
            claims = jwt.validate(token, "refresh");
        } catch (JwtException | IllegalArgumentException exception) {
            return new RefreshResult(null, true);
        }

        UserSession session = sessions.findByRefreshTokenForUpdate(token).orElse(null);
        if (session == null) {
            return new RefreshResult(null, true);
        }

        if (session.getStatus() == SessionStatus.USED) {
            if (session.getRefreshTokenExpiry().isAfter(Instant.now())) {
                session.setStatus(SessionStatus.REVOKED);
                sessions.saveAndFlush(session);
            }
            return new RefreshResult(null, true);
        }

        if (session.getStatus() != SessionStatus.ACTIVE
                || !session.getRefreshTokenExpiry().isAfter(Instant.now())
                || !session.getUsername().equals(claims.getSubject())) {
            return new RefreshResult(null, true);
        }

        User user = users.findByUsername(claims.getSubject())
                .filter(User::isEnabled)
                .orElse(null);

        if (user == null) {
            return new RefreshResult(null, true);
        }

        session.setStatus(SessionStatus.USED);
        sessions.save(session);

        TokenPair pair = createAndSave(user.getUsername(), session.getDeviceId());
        return new RefreshResult(pair, false);
    }
}
