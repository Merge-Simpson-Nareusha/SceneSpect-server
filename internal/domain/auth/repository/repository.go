// Package repository는 인증 데이터의 PostgreSQL 쿼리와 트랜잭션을 담당합니다.
// 서비스에서 요구하는 메서드를 구현하며 HTTP 요청이나 쿠키를 직접 다루지 않습니다.
package repository

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresAuthRepository struct{ Pool *pgxpool.Pool }

// NewPostgresAuthRepository는 연결 풀의 수명은 main이 관리하고, repository는
// 쿼리 실행만 담당하도록 의존성을 주입합니다.
func NewPostgresAuthRepository(pool *pgxpool.Pool) *PostgresAuthRepository {
	return &PostgresAuthRepository{Pool: pool}
}

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
