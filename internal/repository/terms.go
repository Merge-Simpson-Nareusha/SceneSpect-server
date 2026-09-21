package repository

import (
	"context"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain"
)

func (r *PostgresAuthRepository) Terms(ctx context.Context) ([]domain.Term, error) {
	rows, err := r.Pool.Query(ctx, `SELECT id,code,version,title,content,required FROM terms WHERE active ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var terms []domain.Term
	for rows.Next() {
		var term domain.Term
		if err := rows.Scan(&term.ID, &term.Code, &term.Version, &term.Title, &term.Content, &term.Required); err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return terms, rows.Err()
}
