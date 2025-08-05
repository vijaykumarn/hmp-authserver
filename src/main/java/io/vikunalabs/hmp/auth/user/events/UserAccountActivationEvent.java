package io.vikunalabs.hmp.auth.user.events;

import java.io.Serializable;

public record UserAccountActivationEvent(Long userProfileId) implements Serializable {}
