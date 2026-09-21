package migrations

import (
	"context"
	"database/sql"
	"embed"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed *.sql
var files embed.FS

// Up은 서버 실행과 분리된 명령으로 호출합니다. 배포 시 스키마 변경을 명시적으로 검토할 수 있습니다.
func Up(ctx context.Context, databaseURL string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}
