package zadanie1.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import zadanie1.model.User;
import zadanie1.service.AuthService;
import zadanie1.service.TokenService;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService auth;
    private final TokenService tokens;

    public AuthController(AuthService auth, TokenService tokens) {
        this.auth = auth;
        this.tokens = tokens;
    }

    public record RegisterRequest(
            String username,
            String password,
            String fullName,
            String email,
            String phone,
            String deviceId
    ) {
    }

    public record LoginRequest(String username, String password, String deviceId) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    @PostMapping("/register")
    public ResponseEntity<TokenService.TokenPair> register(@RequestBody RegisterRequest request) {
        if (request == null || isBlank(request.username()) || isBlank(request.password())) {
            throw new IllegalArgumentException("username and password are required");
        }

        TokenService.TokenPair pair = tokens.register(
                request.username(),
                request.password(),
                request.fullName(),
                request.email(),
                request.phone(),
                request.deviceId(),
                auth
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(pair);
    }

    @PostMapping("/login")
    public TokenService.TokenPair login(@RequestBody LoginRequest request) {
        if (request == null || isBlank(request.username()) || isBlank(request.password())) {
            throw new IllegalArgumentException("username and password are required");
        }

        User user = auth.authenticate(request.username(), request.password());
        return tokens.issue(user.getUsername(), request.deviceId());
    }

    @PostMapping("/refresh")
    public TokenService.TokenPair refresh(@RequestBody RefreshRequest request) {
        if (request == null || isBlank(request.refreshToken())) {
            throw new IllegalArgumentException("refreshToken is required");
        }

        TokenService.RefreshResult result = tokens.refresh(request.refreshToken());
        if (result.rejected()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh session");
        }

        return result.pair();
    }

    @GetMapping("/csrf")
    public Map<String, String> csrf(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        return Map.of(
                "token", token == null ? "" : token.getToken(),
                "headerName", token == null ? "X-XSRF-TOKEN" : token.getHeaderName()
        );
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
