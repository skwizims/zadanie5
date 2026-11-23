package zadanie1.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import zadanie1.model.Role;
import zadanie1.model.User;
import zadanie1.repository.UserRepository;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User authenticate(String username, String rawPassword) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!user.isEnabled() || !passwordEncoder.matches(rawPassword, user.getPassword())) throw new IllegalArgumentException("Invalid credentials");
        return user;
    }

    public User register(String username, String rawPassword, String fullName, String email, String phone) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (userRepository.existsByUsername(username)) {
            throw new IllegalStateException("Username already taken");
        }
        if (rawPassword == null || !rawPassword.matches("^(?=.*[A-Za-z])(?=.*\\d).{8,}$")) {
            throw new IllegalArgumentException("Password too weak: min 8 chars, at least one letter and one digit");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole(Role.USER);
        user.setEnabled(true);
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPhone(phone);

        return userRepository.save(user);
    }
}