package io.vikunalabs.hmp.auth.user.domain;

public enum LogoutReason {
    USER_LOGOUT,
    SESSION_EXPIRED,
    SECURITY_VIOLATION,
    IP_ADDRESS_CHANGE,
    USER_AGENT_CHANGE,
    CONCURRENT_SESSION_LIMIT,
    ADMIN_REVOKE,
    PASSWORD_CHANGE,
    ACCOUNT_DISABLED
}
