package repository

import (
	"context"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/auth/model"
)

// Terms는 가입 화면과 동의 검증에 사용할 현재 활성 약관을 조회합니다.
func (r *PostgresAuthRepository) Terms(ctx context.Context) ([]model.Term, error) {
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
