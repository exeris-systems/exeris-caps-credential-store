-- Credential Store PostgreSQL Schema (ADR-099, Obligation 9)
-- Layer 5 Domain Primitive: exeris-caps-credential-store

CREATE TABLE IF NOT EXISTS credential_records (
    subject_id UUID PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    token_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS account_verification_tokens (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_verification_tokens_subject_created
    ON account_verification_tokens (subject_id, created_at DESC);

CREATE TABLE IF NOT EXISTS credential_reset_tokens (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_reset_tokens_subject_created
    ON credential_reset_tokens (subject_id, created_at DESC);
