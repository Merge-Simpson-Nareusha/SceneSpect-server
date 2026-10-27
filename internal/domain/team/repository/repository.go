package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/team/model"
)

type PostgresRepository struct{ Pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{Pool: pool}
}

func normalizeError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ErrNotFound
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return model.ErrConflict
	}
	return err
}

func (r *PostgresRepository) Create(ctx context.Context, userID, nickname, joinCode string, input model.CreateTeam) (model.Team, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return model.Team{}, err
	}
	defer tx.Rollback(ctx)

	team := model.Team{JoinCode: joinCode}
	err = tx.QueryRow(ctx, `INSERT INTO teams(id,name,description,join_code,created_by) VALUES(gen_random_uuid(),$1,$2,$3,$4)
		RETURNING id,name,description,youtube_url,guideline,avatar_url,join_code,created_at,updated_at`, input.Name, input.Description, joinCode, userID).
		Scan(&team.ID, &team.Name, &team.Description, &team.YouTubeURL, &team.Guideline, &team.AvatarURL, &team.JoinCode, &team.CreatedAt, &team.UpdatedAt)
	if err != nil {
		return model.Team{}, normalizeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO team_members(team_id,user_id,nickname,role,can_create_projects) VALUES($1,$2,$3,'LEADER',true)`, team.ID, userID, nickname); err != nil {
		return model.Team{}, normalizeError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return model.Team{}, normalizeError(err)
	}
	team.Role = model.LeaderRole
	team.MemberCount = 1
	return team, nil
}

func (r *PostgresRepository) List(ctx context.Context, userID string) ([]model.Team, error) {
	rows, err := r.Pool.Query(ctx, `SELECT t.id,t.name,t.description,t.youtube_url,t.guideline,t.avatar_url,tm.role,
		(SELECT count(*)::int FROM team_members all_members WHERE all_members.team_id=t.id),tm.sort_order,t.created_at,t.updated_at
		FROM team_members tm JOIN teams t ON t.id=tm.team_id WHERE tm.user_id=$1 ORDER BY tm.sort_order,t.created_at,t.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	teams := make([]model.Team, 0)
	for rows.Next() {
		var team model.Team
		var sortOrder int
		if err := rows.Scan(&team.ID, &team.Name, &team.Description, &team.YouTubeURL, &team.Guideline, &team.AvatarURL, &team.Role, &team.MemberCount, &sortOrder, &team.CreatedAt, &team.UpdatedAt); err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}
	return teams, rows.Err()
}

func (r *PostgresRepository) Get(ctx context.Context, userID, teamID string) (model.Team, error) {
	var team model.Team
	err := r.Pool.QueryRow(ctx, `SELECT t.id,t.name,t.description,t.youtube_url,t.guideline,t.avatar_url,t.join_code,tm.role,
		(SELECT count(*)::int FROM team_members all_members WHERE all_members.team_id=t.id),t.created_at,t.updated_at
		FROM teams t JOIN team_members tm ON tm.team_id=t.id WHERE t.id=$1 AND tm.user_id=$2`, teamID, userID).
		Scan(&team.ID, &team.Name, &team.Description, &team.YouTubeURL, &team.Guideline, &team.AvatarURL, &team.JoinCode, &team.Role, &team.MemberCount, &team.CreatedAt, &team.UpdatedAt)
	return team, normalizeError(err)
}

func (r *PostgresRepository) NameAvailable(ctx context.Context, name, excludeTeamID string) (bool, error) {
	var available bool
	err := r.Pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM teams WHERE lower(name)=lower($1) AND ($2='' OR id<>$2))`, name, excludeTeamID).Scan(&available)
	return available, err
}

func (r *PostgresRepository) Update(ctx context.Context, userID, teamID string, input model.UpdateTeam) (model.Team, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return model.Team{}, err
	}
	defer tx.Rollback(ctx)
	if err = requireManagerTx(ctx, tx, userID, teamID); err != nil {
		return model.Team{}, err
	}
	var team model.Team
	err = tx.QueryRow(ctx, `UPDATE teams t SET name=$1,description=$2,youtube_url=$3,guideline=$4,avatar_url=$5,updated_at=now()
		WHERE t.id=$6
		RETURNING t.id,t.name,t.description,t.youtube_url,t.guideline,t.avatar_url,t.join_code,t.updated_at`, input.Name, input.Description, input.YouTubeURL, input.Guideline, input.AvatarURL, teamID).
		Scan(&team.ID, &team.Name, &team.Description, &team.YouTubeURL, &team.Guideline, &team.AvatarURL, &team.JoinCode, &team.UpdatedAt)
	if err != nil {
		return model.Team{}, normalizeError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return model.Team{}, normalizeError(err)
	}
	return team, nil
}

func (r *PostgresRepository) Delete(ctx context.Context, userID, teamID string) error {
	tag, err := r.Pool.Exec(ctx, `DELETE FROM teams t WHERE t.id=$1 AND EXISTS(SELECT 1 FROM team_members tm WHERE tm.team_id=t.id AND tm.user_id=$2 AND tm.role='LEADER')`, teamID, userID)
	if err != nil {
		return normalizeError(err)
	}
	if tag.RowsAffected() == 0 {
		return model.ErrForbidden
	}
	return nil
}

func (r *PostgresRepository) RequestJoin(ctx context.Context, userID, joinCode, nickname string) (model.JoinRequest, error) {
	var request model.JoinRequest
	request.UserID = userID
	request.Nickname = nickname
	err := r.Pool.QueryRow(ctx, `INSERT INTO team_join_requests(id,team_id,user_id,nickname)
		SELECT gen_random_uuid(),t.id,$1,$2 FROM teams t
		WHERE t.join_code=$3 AND NOT EXISTS(SELECT 1 FROM team_members tm WHERE tm.team_id=t.id AND tm.user_id=$1)
		ON CONFLICT (team_id,user_id) DO UPDATE SET nickname=EXCLUDED.nickname,status='PENDING',reviewed_by=NULL,created_at=now(),reviewed_at=NULL
		WHERE team_join_requests.status IN ('REJECTED','ACCEPTED')
		RETURNING id,team_id,user_id,nickname,status,created_at`, userID, nickname, joinCode).
		Scan(&request.ID, &request.TeamID, &request.UserID, &request.Nickname, &request.Status, &request.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var codeExists bool
			if queryErr := r.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams WHERE join_code=$1)`, joinCode).Scan(&codeExists); queryErr != nil {
				return model.JoinRequest{}, queryErr
			}
			if !codeExists {
				return model.JoinRequest{}, model.ErrNotFound
			}
			return model.JoinRequest{}, model.ErrConflict
		}
		return model.JoinRequest{}, normalizeError(err)
	}
	return request, nil
}

func (r *PostgresRepository) Requests(ctx context.Context, actorID, teamID string) ([]model.JoinRequest, error) {
	if err := r.requireManager(ctx, actorID, teamID); err != nil {
		return nil, err
	}
	rows, err := r.Pool.Query(ctx, `SELECT jr.id,jr.team_id,t.name,jr.user_id,jr.nickname,jr.status,jr.created_at
		FROM team_join_requests jr JOIN teams t ON t.id=jr.team_id WHERE jr.team_id=$1 AND jr.status='PENDING' ORDER BY jr.created_at,jr.id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := make([]model.JoinRequest, 0)
	for rows.Next() {
		var request model.JoinRequest
		if err := rows.Scan(&request.ID, &request.TeamID, &request.TeamName, &request.UserID, &request.Nickname, &request.Status, &request.CreatedAt); err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (r *PostgresRepository) ReviewRequest(ctx context.Context, actorID, teamID, requestID string, accept bool) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManagerTx(ctx, tx, actorID, teamID); err != nil {
		return err
	}
	var userID, nickname string
	var status model.RequestStatus
	err = tx.QueryRow(ctx, `SELECT user_id,nickname,status FROM team_join_requests WHERE id=$1 AND team_id=$2 FOR UPDATE`, requestID, teamID).Scan(&userID, &nickname, &status)
	if err != nil {
		return normalizeError(err)
	}
	if status != model.PendingStatus {
		return model.ErrConflict
	}
	newStatus := model.RejectedStatus
	if accept {
		newStatus = model.AcceptedStatus
		if _, err := tx.Exec(ctx, `INSERT INTO team_members(team_id,user_id,nickname) VALUES($1,$2,$3)`, teamID, userID, nickname); err != nil {
			return normalizeError(err)
		}
	}
	_, err = tx.Exec(ctx, `UPDATE team_join_requests SET status=$1,reviewed_by=$2,reviewed_at=now() WHERE id=$3`, newStatus, actorID, requestID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) Members(ctx context.Context, actorID, teamID string) ([]model.Member, error) {
	if _, err := r.Get(ctx, actorID, teamID); err != nil {
		return nil, err
	}
	rows, err := r.Pool.Query(ctx, `SELECT tm.user_id,tm.nickname,COALESCE(u.avatar_url,''),tm.role,tm.warning_count,tm.can_create_projects,tm.joined_at
		FROM team_members tm JOIN users u ON u.id=tm.user_id WHERE tm.team_id=$1
		ORDER BY CASE tm.role WHEN 'LEADER' THEN 0 WHEN 'DEPUTY' THEN 1 ELSE 2 END,tm.joined_at,tm.user_id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := make([]model.Member, 0)
	for rows.Next() {
		var member model.Member
		if err := rows.Scan(&member.UserID, &member.Nickname, &member.AvatarURL, &member.Role, &member.WarningCount, &member.CanCreateProjects, &member.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (r *PostgresRepository) SetRole(ctx context.Context, actorID, teamID, targetID string, role model.Role) error {
	if role != model.LeaderRole && role != model.DeputyRole && role != model.MemberRole {
		return model.ErrInvalid
	}
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actorRole model.Role
	if err = tx.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, actorID).Scan(&actorRole); err != nil {
		return normalizeError(err)
	}
	if actorRole != model.LeaderRole || targetID == actorID {
		return model.ErrForbidden
	}
	var targetExists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id=$1 AND user_id=$2)`, teamID, targetID).Scan(&targetExists); err != nil {
		return err
	}
	if !targetExists {
		return model.ErrNotFound
	}
	if role == model.LeaderRole {
		if _, err = tx.Exec(ctx, `UPDATE team_members SET role='MEMBER' WHERE team_id=$1 AND role='LEADER'`, teamID); err != nil {
			return err
		}
	} else if role == model.DeputyRole {
		if _, err = tx.Exec(ctx, `UPDATE team_members SET role='MEMBER' WHERE team_id=$1 AND role='DEPUTY'`, teamID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE team_members SET role=$1,can_create_projects=CASE WHEN $1 IN ('LEADER','DEPUTY') THEN true ELSE can_create_projects END WHERE team_id=$2 AND user_id=$3`, role, teamID, targetID); err != nil {
		return normalizeError(err)
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) SetProjectCreation(ctx context.Context, actorID, teamID, targetID string, allowed bool) error {
	var actorRole model.Role
	err := r.Pool.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2`, teamID, actorID).Scan(&actorRole)
	if err != nil {
		return normalizeError(err)
	}
	if actorRole != model.LeaderRole {
		return model.ErrForbidden
	}
	tag, err := r.Pool.Exec(ctx, `UPDATE team_members SET can_create_projects=$1 WHERE team_id=$2 AND user_id=$3 AND role='MEMBER'`, allowed, teamID, targetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (r *PostgresRepository) RemoveMember(ctx context.Context, actorID, teamID, targetID string) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actorRole, targetRole model.Role
	if err = tx.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, actorID).Scan(&actorRole); err != nil {
		return normalizeError(err)
	}
	if err = tx.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, targetID).Scan(&targetRole); err != nil {
		return normalizeError(err)
	}
	if actorID == targetID {
		if targetRole == model.LeaderRole {
			return model.ErrConflict
		}
	} else if actorRole != model.LeaderRole && !(actorRole == model.DeputyRole && targetRole == model.MemberRole) {
		return model.ErrForbidden
	}
	tag, err := tx.Exec(ctx, `DELETE FROM team_members WHERE team_id=$1 AND user_id=$2 AND role<>'LEADER'`, teamID, targetID)
	if err != nil {
		return normalizeError(err)
	}
	if tag.RowsAffected() != 1 {
		return model.ErrConflict
	}
	if _, err = tx.Exec(ctx, `DELETE FROM project_permissions pp USING projects p
		WHERE pp.project_id=p.id AND p.team_id=$1 AND pp.user_id=$2`, teamID, targetID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE project_access_requests ar SET status='REJECTED',reviewed_by=NULL,reviewed_at=now()
		FROM projects p WHERE ar.project_id=p.id AND p.team_id=$1 AND ar.user_id=$2 AND ar.status='PENDING'`, teamID, targetID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) WarnMember(ctx context.Context, actorID, teamID, targetID string) (int, error) {
	if err := r.requireManager(ctx, actorID, teamID); err != nil {
		return 0, err
	}
	var count int
	err := r.Pool.QueryRow(ctx, `UPDATE team_members SET warning_count=warning_count+1 WHERE team_id=$1 AND user_id=$2 AND role='MEMBER' RETURNING warning_count`, teamID, targetID).Scan(&count)
	return count, normalizeError(err)
}

func (r *PostgresRepository) Reorder(ctx context.Context, userID string, teamIDs []string) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for index, teamID := range teamIDs {
		tag, err := tx.Exec(ctx, `UPDATE team_members SET sort_order=$1 WHERE user_id=$2 AND team_id=$3`, index, userID, teamID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return model.ErrNotFound
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) requireManager(ctx context.Context, userID, teamID string) error {
	return requireManager(ctx, r.Pool, userID, teamID)
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func requireManager(ctx context.Context, query queryRower, userID, teamID string) error {
	var role model.Role
	err := query.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2`, teamID, userID).Scan(&role)
	if err != nil {
		return normalizeError(err)
	}
	if role != model.LeaderRole && role != model.DeputyRole {
		return model.ErrForbidden
	}
	return nil
}

func requireManagerTx(ctx context.Context, tx pgx.Tx, userID, teamID string) error {
	var role model.Role
	err := tx.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, userID).Scan(&role)
	if err != nil {
		return normalizeError(err)
	}
	if role != model.LeaderRole && role != model.DeputyRole {
		return model.ErrForbidden
	}
	return nil
}
