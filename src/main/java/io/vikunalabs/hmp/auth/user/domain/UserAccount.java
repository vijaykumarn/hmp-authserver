package io.vikunalabs.hmp.auth.user.domain;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "user_accounts", schema = "hmp")
@EntityListeners(AuditingEntityListener.class)
public class UserAccount implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Version
    private int version;

    @Id
    private Long id;

    private String username;
    private String password;
    private String email;
    private boolean emailVerified;

    @Builder.Default
    private String provider = "local";
    private String providerId;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    private UserRole role = UserRole.USER;

    private boolean accountEnabled;
    private boolean credentialsExpired;
    private boolean accountExpired;
    private boolean accountLocked;

    private Instant lastLogin;
    private boolean rememberMe;

    @OneToOne
    @MapsId
    @JoinColumn(name = "id")
    @JsonBackReference
    private UserProfile userProfile;

    @Builder.Default
    @OneToMany(mappedBy = "userAccount", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Token> tokens = new ArrayList<>();


}
