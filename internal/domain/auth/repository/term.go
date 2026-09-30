package repository

import (
	"context"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
)

func (r *PostgresAuthRepository) Terms(ctx context.Context) ([]model.Term, error) {
	// active 약관만 읽어 가입 화면과 가입 완료 검증이 같은 버전을 사용하게 합니다.
	rows, err := r.Pool.Query(ctx, `SELECT id,code,version,title,content,required FROM terms WHERE active ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var terms []model.Term
	for rows.Next() {
		var term model.Term
		if err := rows.Scan(&term.ID, &term.Code, &term.Version, &term.Title, &term.Content, &term.Required); err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return terms, rows.Err()
}
