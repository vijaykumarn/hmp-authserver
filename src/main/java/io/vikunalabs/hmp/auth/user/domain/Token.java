package io.vikunalabs.hmp.auth.user.domain;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "tokens", schema = "hmp")
@EntityListeners(AuditingEntityListener.class)
public class Token implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Version
    private int version;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private UUID value;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    private TokenStatus status = TokenStatus.PENDING;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_account_id")
    private UserAccount userAccount;

    @CreatedDate
    private Instant createdAt;

    private Instant expiresAt;
    private Instant confirmedAt;

    public Token(UserAccount userAccount, TokenType tokenType, Instant expiresAt) {
        this.value = UUID.randomUUID();
        this.tokenType = tokenType;
        this.userAccount = userAccount;
        this.expiresAt = expiresAt;
        this.status = TokenStatus.PENDING;
    }

    // Helper methods
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return status == TokenStatus.PENDING && !isExpired();
    }

    public void confirm() {
        this.status = TokenStatus.CONFIRMED;
        this.confirmedAt = Instant.now();
    }

    public void revoke() {
        this.status = TokenStatus.REVOKED;
    }
}
