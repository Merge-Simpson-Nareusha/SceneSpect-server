-- +goose Up
CREATE TABLE oauth_accounts (
    provider VARCHAR(10) NOT NULL CHECK (provider IN ('GOOGLE', 'KAKAO', 'X', 'APPLE')),
    provider_user_id TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id),
    UNIQUE (user_id, provider)
);
CREATE INDEX oauth_accounts_user_id_idx ON oauth_accounts(user_id);

-- +goose Down
DROP TABLE oauth_accounts;
