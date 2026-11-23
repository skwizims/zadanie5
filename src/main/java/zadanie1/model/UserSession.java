package zadanie1.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions", indexes = @Index(name="idx_user_sessions_username", columnList="username"),
       uniqueConstraints = @UniqueConstraint(name="uk_user_sessions_refresh_token", columnNames="refresh_token"))
public class UserSession {
    @Id @GeneratedValue(strategy = GenerationType.UUID) private UUID id;
    @Column(nullable=false) private String username;
    @Column(name="device_id") private String deviceId;
    @Column(name="access_token", nullable=false, columnDefinition="TEXT") private String accessToken;
    @Column(name="refresh_token", nullable=false, unique=true, columnDefinition="TEXT") private String refreshToken;
    @Column(name="access_token_expiry", nullable=false) private Instant accessTokenExpiry;
    @Column(name="refresh_token_expiry", nullable=false) private Instant refreshTokenExpiry;
    @Enumerated(EnumType.STRING) @Column(nullable=false) private SessionStatus status;
    public UUID getId(){return id;} public String getUsername(){return username;} public void setUsername(String v){username=v;}
    public String getDeviceId(){return deviceId;} public void setDeviceId(String v){deviceId=v;}
    public String getAccessToken(){return accessToken;} public void setAccessToken(String v){accessToken=v;}
    public String getRefreshToken(){return refreshToken;} public void setRefreshToken(String v){refreshToken=v;}
    public Instant getAccessTokenExpiry(){return accessTokenExpiry;} public void setAccessTokenExpiry(Instant v){accessTokenExpiry=v;}
    public Instant getRefreshTokenExpiry(){return refreshTokenExpiry;} public void setRefreshTokenExpiry(Instant v){refreshTokenExpiry=v;}
    public SessionStatus getStatus(){return status;} public void setStatus(SessionStatus v){status=v;}
}
