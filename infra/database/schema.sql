-- Create schema if not exists
DROP SCHEMA IF EXISTS hmp CASCADE;
CREATE SCHEMA IF NOT EXISTS hmp;

SET search_path TO hmp;

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-----------------------------------------------------------
----------- SPRING MODULITH - EVENT PUBLICATION -----------
-----------------------------------------------------------
CREATE TABLE hmp.event_publication
(
    id               UUID                     NOT NULL,
    listener_id      TEXT                     NOT NULL,
    event_type       TEXT                     NOT NULL,
    serialized_event TEXT                     NOT NULL,
    publication_date TIMESTAMP WITH TIME ZONE NOT NULL,
    completion_date  TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id)
);

-----------------------------------------------------------
--------------------- OAUTH2 CLIENTS  ---------------------
-----------------------------------------------------------

CREATE TABLE IF NOT EXISTS hmp.oauth2_registered_client
(
    id                            VARCHAR(100) PRIMARY KEY,
    client_id                     VARCHAR(100) NOT NULL,
    client_id_issued_at           TIMESTAMP,
    client_secret                 VARCHAR(200),
    client_secret_expires_at      TIMESTAMP,
    client_name                   VARCHAR(200),
    client_authentication_methods TEXT         NOT NULL,
    authorization_grant_types     TEXT         NOT NULL,
    redirect_uris                 TEXT         NOT NULL,
    post_logout_redirect_uris     TEXT,
    front_channel_logout_uri      VARCHAR(1000),
    back_channel_logout_uri       VARCHAR(1000),
    scopes                        TEXT         NOT NULL,
    client_settings               TEXT         NOT NULL,
    token_settings                TEXT         NOT NULL
);

-----------------------------------------------------------
----------------- USER ----------------
-----------------------------------------------------------
CREATE TABLE hmp.users
(
    id                    BIGSERIAL PRIMARY KEY,
    version               INTEGER      NOT NULL DEFAULT 0,

    -- Authentication fields
    username              VARCHAR(255) NOT NULL UNIQUE,
    password              VARCHAR(255),
    email                 VARCHAR(255) NOT NULL UNIQUE,
    email_verified        BOOLEAN      NOT NULL DEFAULT FALSE,
    provider              VARCHAR(50)  NOT NULL DEFAULT 'local',
    provider_id           VARCHAR(255),
    role                  VARCHAR(20)  NOT NULL DEFAULT 'USER',

    -- Account status
    account_enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    credentials_expired   BOOLEAN      NOT NULL DEFAULT FALSE,
    account_expired       BOOLEAN      NOT NULL DEFAULT FALSE,
    account_locked        BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Security
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until          TIMESTAMP,
    last_login            TIMESTAMP,
    remember_me           BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Profile fields
    first_name            VARCHAR(100),
    last_name             VARCHAR(100),
    organisation          VARCHAR(100),
    consent               BOOLEAN      NOT NULL DEFAULT FALSE,
    notification          BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Audit fields
    created_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Unique constraints (automatically create indexes)
CREATE UNIQUE INDEX idx_users_email ON hmp.users (email);
CREATE UNIQUE INDEX idx_users_username ON hmp.users (username);

-- Login performance (most important)
CREATE INDEX idx_users_email_enabled ON hmp.users (email) WHERE account_enabled = true AND email_verified = true;
CREATE INDEX idx_users_username_enabled ON hmp.users (username) WHERE account_enabled = true AND email_verified = true;

-- OAuth provider lookups
CREATE UNIQUE INDEX idx_users_provider_id ON hmp.users (provider, provider_id) WHERE provider != 'local';

-- Security and account management
CREATE INDEX idx_users_locked_until ON hmp.users (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX idx_users_failed_attempts ON hmp.users (failed_login_attempts) WHERE failed_login_attempts > 0;

-- Cleanup and maintenance queries
CREATE INDEX idx_users_unverified ON hmp.users (created_at) WHERE email_verified = false;
CREATE INDEX idx_users_inactive ON hmp.users (last_login) WHERE account_enabled = true;

-- Reporting and analytics
CREATE INDEX idx_users_created_at ON hmp.users (created_at);
CREATE INDEX idx_users_role ON hmp.users (role);
CREATE INDEX idx_users_provider ON hmp.users (provider);

-- Composite index for common query patterns
CREATE INDEX idx_users_status ON hmp.users (account_enabled, email_verified, account_locked);

-----------------------------------------------------------
----------------------     TOKENS    ----------------------
-----------------------------------------------------------
CREATE TABLE hmp.tokens
(
    id           BIGSERIAL PRIMARY KEY,
    value        UUID        NOT NULL,
    user_id      BIGINT      NOT NULL,
    token_type   VARCHAR(30) NOT NULL,
    status       VARCHAR(30) NOT NULL DEFAULT 'PENDING',
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    version      INTEGER     NOT NULL DEFAULT 0,
    CONSTRAINT uq_value UNIQUE (value),
    CONSTRAINT fk_tokens_user
        FOREIGN KEY (user_id) REFERENCES hmp.users (id) ON DELETE CASCADE
);

-- Existing indexes
CREATE UNIQUE INDEX idx_tokens_value ON hmp.tokens (value);
CREATE INDEX idx_tokens_user_id ON hmp.tokens (user_id);

-- Performance indexes
CREATE INDEX idx_tokens_user_type_status ON hmp.tokens (user_id, token_type, status);
CREATE INDEX idx_tokens_expires_at ON hmp.tokens (expires_at) WHERE status = 'PENDING';
CREATE INDEX idx_tokens_cleanup ON hmp.tokens (status, expires_at);

-- Rate limiting queries
CREATE INDEX idx_tokens_email_type_created ON hmp.tokens (token_type, created_at)
    INCLUDE (user_id) WHERE status = 'PENDING';

-----------------------------------------------------------
--------------------- USER SESSIONS -------------------
-----------------------------------------------------------


-- Create user_sessions table
CREATE TABLE hmp.user_sessions
(
    id               BIGSERIAL PRIMARY KEY,
    session_id       VARCHAR(255) NOT NULL UNIQUE,
    user_id          BIGINT       NOT NULL REFERENCES hmp.users (id) ON DELETE CASCADE,
    ip_address       VARCHAR(45)  NOT NULL, -- Support IPv6
    user_agent_hash  VARCHAR(64)  NOT NULL,
    created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at       TIMESTAMP    NOT NULL,
    remember_me      BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    logout_reason    VARCHAR(50),           -- 'USER_LOGOUT', 'SECURITY_VIOLATION', 'EXPIRED', 'ADMIN_REVOKE'

    -- Audit fields
    version          INTEGER      NOT NULL DEFAULT 0,
    updated_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_user_sessions_session_id ON hmp.user_sessions (session_id) WHERE is_active = true;
CREATE INDEX idx_user_sessions_user_id ON hmp.user_sessions (user_id) WHERE is_active = true;
CREATE INDEX idx_user_sessions_expires_at ON hmp.user_sessions (expires_at) WHERE is_active = true;
CREATE INDEX idx_user_sessions_last_accessed ON hmp.user_sessions (last_accessed_at) WHERE is_active = true;
CREATE INDEX idx_user_sessions_ip_user ON hmp.user_sessions (ip_address, user_id) WHERE is_active = true;

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for updated_at
CREATE TRIGGER update_user_sessions_updated_at
    BEFORE UPDATE
    ON hmp.user_sessions
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Optional: Create session events audit table
CREATE TABLE hmp.session_events
(
    id              BIGSERIAL PRIMARY KEY,
    session_id      VARCHAR(255) NOT NULL,
    user_id         BIGINT       NOT NULL,
    event_type      VARCHAR(50)  NOT NULL, -- 'CREATED', 'ACCESSED', 'SECURITY_VIOLATION', 'EXPIRED', 'INVALIDATED'
    ip_address      VARCHAR(45)  NOT NULL,
    user_agent_hash VARCHAR(64),
    details         TEXT,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_session_events_session_id ON hmp.session_events (session_id);
CREATE INDEX idx_session_events_user_id ON hmp.session_events (user_id);
CREATE INDEX idx_session_events_created_at ON hmp.session_events (created_at);
