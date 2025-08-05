package io.vikunalabs.hmp.auth.user.events;

import java.io.Serializable;

public record UserRegistrationEvent(Long userProfileId) implements Serializable {}
