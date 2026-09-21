-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE CHECK (email = lower(email)),
    username VARCHAR(50) NOT NULL UNIQUE,
    nickname VARCHAR(50) NOT NULL UNIQUE,
    password_hash TEXT,
    password_version BIGINT NOT NULL DEFAULT 1,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    role VARCHAR(10) NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
    status VARCHAR(10) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'BLOCKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(username) BETWEEN 1 AND 50),
    CHECK (char_length(nickname) BETWEEN 1 AND 50)
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens(user_id);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens(family_id);

CREATE TABLE terms (
    id UUID PRIMARY KEY,
    code VARCHAR(50) NOT NULL,
    version VARCHAR(30) NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    required BOOLEAN NOT NULL,
    active BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (code, version)
);
CREATE UNIQUE INDEX terms_one_active_version_idx ON terms(code) WHERE active;

CREATE TABLE user_terms (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    term_id UUID NOT NULL REFERENCES terms(id),
    accepted BOOLEAN NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, term_id)
);

CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL CHECK (provider IN ('google', 'apple', 'kakao', 'x')),
    provider_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_subject),
    UNIQUE (user_id, provider)
);

INSERT INTO terms (id, code, version, title, content, required, active) VALUES
    ('00000000-0000-0000-0000-000000000001', 'service', '1.0', '서비스 이용약관', 'SceneSpect 서비스 이용약관입니다.', true, true),
    ('00000000-0000-0000-0000-000000000002', 'privacy', '1.0', '개인정보 수집 및 이용', 'SceneSpect 개인정보 처리 안내입니다.', true, true),
    ('00000000-0000-0000-0000-000000000003', 'marketing', '1.0', '마케팅 정보 수신', '새 소식과 혜택 안내를 받을 수 있습니다.', false, true)
ON CONFLICT (code, version) DO NOTHING;

-- +goose Down
DROP TABLE oauth_accounts;
DROP TABLE user_terms;
DROP TABLE terms;
DROP TABLE refresh_tokens;
DROP TABLE users;
DROP EXTENSION IF EXISTS pgcrypto;
