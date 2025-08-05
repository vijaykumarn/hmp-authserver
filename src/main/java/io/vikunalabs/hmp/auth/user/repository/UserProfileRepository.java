package io.vikunalabs.hmp.auth.user.repository;

import io.vikunalabs.hmp.auth.user.domain.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, Long> {}
