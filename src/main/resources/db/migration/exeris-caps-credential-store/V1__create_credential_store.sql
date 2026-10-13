-- exeris-caps-credential-store, schema version 1.
--
-- Data scope: deployment-global (ADR-059 GLOBAL). A subject has one credential however many tenants it is a
-- member of (ADR-099 obligation 10), so these tables carry no tenant_id and no row-level-security policy.
-- Tenant isolation (ADR-012) applies to tenant membership and role grants, which the multi-tenancy and
-- rbac-policy capabilities own; this capability never reads or filters by tenant.
--
-- Tokens are stored as SHA-256 hashes only (ADR-099 obligation 9). consumed_at is the time a token stopped
-- being usable: consumed, or superseded by a newer token of the same kind.

CREATE TABLE IF NOT EXISTS credential_records (
    subject_id                UUID         PRIMARY KEY,
    login_identifier          VARCHAR(320) NOT NULL,
    password_hash             VARCHAR(255) NOT NULL,
    email_verified            BOOLEAN      NOT NULL DEFAULT FALSE,
    verified_at               TIMESTAMPTZ,
    failed_login_attempts     INT          NOT NULL DEFAULT 0,
    failure_window_started_at TIMESTAMPTZ,
    locked_until              TIMESTAMPTZ,
    token_version             BIGINT       NOT NULL DEFAULT 1,
    created_at                TIMESTAMPTZ  NOT NULL,
    updated_at                TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_credential_records_login_identifier UNIQUE (login_identifier),
    CONSTRAINT chk_credential_records_failed_login_attempts CHECK (failed_login_attempts >= 0),
    CONSTRAINT chk_credential_records_token_version CHECK (token_version >= 1)
);

CREATE TABLE IF NOT EXISTS account_verification_tokens (
    id          UUID        PRIMARY KEY,
    subject_id  UUID        NOT NULL REFERENCES credential_records (subject_id) ON DELETE CASCADE,
    token_hash  CHAR(64)    NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT uq_account_verification_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_account_verification_tokens_subject_created
    ON account_verification_tokens (subject_id, created_at DESC);

CREATE TABLE IF NOT EXISTS credential_reset_tokens (
    id          UUID        PRIMARY KEY,
    subject_id  UUID        NOT NULL REFERENCES credential_records (subject_id) ON DELETE CASCADE,
    token_hash  CHAR(64)    NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT uq_credential_reset_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_credential_reset_tokens_subject_created
    ON credential_reset_tokens (subject_id, created_at DESC);
