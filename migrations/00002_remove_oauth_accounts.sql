-- +goose Up
-- OAuth는 현재 범위에서 제외했으므로 이전 개발 migration의 잔여 테이블을 정리합니다.
DROP TABLE IF EXISTS oauth_accounts;

-- +goose Down
-- OAuth 스키마는 이후 별도 기능으로 설계하고 새 migration으로 추가합니다.
SELECT 1;
