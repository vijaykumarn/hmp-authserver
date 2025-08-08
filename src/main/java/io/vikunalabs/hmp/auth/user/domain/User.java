package io.vikunalabs.hmp.auth.user.domain;

import jakarta.persistence.*;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "users", schema = "hmp")
@EntityListeners(AuditingEntityListener.class)
public class User implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Version
    private int version;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Authentication fields (from UserAccount)
    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Builder.Default
    private boolean emailVerified = false;

    @Builder.Default
    private String provider = "local";

    private String providerId;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    private UserRole role = UserRole.USER;

    @Builder.Default
    private boolean accountEnabled = true;

    @Builder.Default
    private boolean credentialsExpired = false;

    @Builder.Default
    private boolean accountExpired = false;

    @Builder.Default
    private boolean accountLocked = false;

    private Instant lastLogin;

    @Builder.Default
    private boolean rememberMe = false;

    // Security fields
    @Builder.Default
    private int failedLoginAttempts = 0;

    private Instant lockedUntil;

    // Profile fields (from UserProfile)
    private String firstName;
    private String lastName;
    private String organisation;

    @Builder.Default
    private boolean consent = false;

    @Builder.Default
    private boolean notification = false;

    // Audit fields
    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Relationships
    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Token> tokens = new ArrayList<>();

    // Convenience methods
    public String getFullName() {
        if (firstName == null && lastName == null) {
            return username;
        }
        return String.format("%s %s", firstName != null ? firstName : "", lastName != null ? lastName : "")
                .trim();
    }

    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    public boolean isAccountNonLocked() {
        return !accountLocked && (lockedUntil == null || Instant.now().isAfter(lockedUntil));
    }

    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    public boolean isEnabled() {
        return accountEnabled && emailVerified;
    }
}
