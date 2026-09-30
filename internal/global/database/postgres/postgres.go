// Package postgres는 PostgreSQL 연결 풀 생성과 시작 시 연결 검증을 담당합니다.
// 사용자·약관·토큰의 실제 SQL은 각 도메인 repository에 둡니다.
package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgres는 PostgreSQL 연결 풀을 만들고 실제 접속을 확인합니다.
// 서버가 요청을 받기 시작한 다음 DB 장애가 발견되는 대신, 의존 서비스가 준비되지 않으면
// 애플리케이션 시작 단계에서 실패하도록 합니다. 성공한 풀의 종료는 호출자가 담당합니다.
func NewPostgres(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	// 서버가 포트를 열기 전에 Ping을 수행해 DB 미연결 상태를 조기에 실패시킵니다.
	// pool의 Close는 main의 수명 관리 책임이므로 생성 함수는 실패 시에만 닫습니다.
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}
