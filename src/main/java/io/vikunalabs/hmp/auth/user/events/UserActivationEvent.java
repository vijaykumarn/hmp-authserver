package io.vikunalabs.hmp.auth.user.events;

import java.io.Serializable;

public record UserActivationEvent(Long userId) implements Serializable {}
