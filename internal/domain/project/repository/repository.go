package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Merge-Simpson-Nareusha/SceneSpect-server/internal/domain/project/model"
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

func (r *PostgresRepository) Create(ctx context.Context, userID, teamID string, input model.CreateProject) (model.Project, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return model.Project{}, err
	}
	defer tx.Rollback(ctx)
	var role string
	var canCreate bool
	err = tx.QueryRow(ctx, `SELECT role,can_create_projects FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, userID).Scan(&role, &canCreate)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Project{}, model.ErrNotFound
	}
	if err != nil {
		return model.Project{}, err
	}
	if role != "LEADER" && role != "DEPUTY" && !canCreate {
		return model.Project{}, model.ErrForbidden
	}
	var project model.Project
	err = tx.QueryRow(ctx, `INSERT INTO projects(id,team_id,name,description,thumbnail_url,visibility,created_by)
		VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6)
		RETURNING id,team_id,name,description,thumbnail_url,visibility,created_by,created_at,updated_at`, teamID, input.Name, input.Description, input.ThumbnailURL, input.Visibility, userID).
		Scan(&project.ID, &project.TeamID, &project.Name, &project.Description, &project.ThumbnailURL, &project.Visibility, &project.CreatedBy, &project.CreatedAt, &project.UpdatedAt)
	if err != nil {
		return model.Project{}, normalizeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO project_permissions(project_id,user_id,access_level,granted_by) VALUES($1,$2,'EDITOR',$2)`, project.ID, userID); err != nil {
		return model.Project{}, normalizeError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return model.Project{}, normalizeError(err)
	}
	project.AccessLevel = model.EditorAccess
	if role == "LEADER" || role == "DEPUTY" {
		project.AccessLevel = model.ManagerAccess
	}
	return project, nil
}

func (r *PostgresRepository) List(ctx context.Context, userID, teamID, sort string) ([]model.Project, error) {
	if _, err := r.teamRole(ctx, userID, teamID); err != nil {
		return nil, err
	}
	order := "p.created_at DESC,p.id"
	if sort == "name" {
		order = "lower(p.name),p.id"
	}
	rows, err := r.Pool.Query(ctx, `SELECT p.id,p.team_id,p.name,p.description,p.thumbnail_url,p.visibility,p.created_by,
		CASE WHEN tm.role IN ('LEADER','DEPUTY') THEN 'MANAGER' WHEN pp.access_level IS NOT NULL THEN pp.access_level WHEN p.visibility='TEAM' THEN 'VIEWER' ELSE '' END,
		p.created_at,p.updated_at
		FROM projects p JOIN team_members tm ON tm.team_id=p.team_id AND tm.user_id=$2
		LEFT JOIN project_permissions pp ON pp.project_id=p.id AND pp.user_id=$2
		WHERE p.team_id=$1 AND (tm.role IN ('LEADER','DEPUTY') OR pp.access_level IS NOT NULL OR p.visibility='TEAM')
		ORDER BY `+order, teamID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := make([]model.Project, 0)
	for rows.Next() {
		var project model.Project
		if err := rows.Scan(&project.ID, &project.TeamID, &project.Name, &project.Description, &project.ThumbnailURL, &project.Visibility, &project.CreatedBy, &project.AccessLevel, &project.CreatedAt, &project.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

func (r *PostgresRepository) Get(ctx context.Context, userID, projectID string) (model.Project, error) {
	var project model.Project
	err := r.Pool.QueryRow(ctx, `SELECT p.id,p.team_id,p.name,p.description,p.thumbnail_url,p.visibility,p.created_by,
		CASE WHEN tm.role IN ('LEADER','DEPUTY') THEN 'MANAGER' WHEN pp.access_level IS NOT NULL THEN pp.access_level WHEN p.visibility='TEAM' THEN 'VIEWER' ELSE '' END,
		p.created_at,p.updated_at
		FROM projects p JOIN team_members tm ON tm.team_id=p.team_id AND tm.user_id=$2
		LEFT JOIN project_permissions pp ON pp.project_id=p.id AND pp.user_id=$2
		WHERE p.id=$1 AND (tm.role IN ('LEADER','DEPUTY') OR pp.access_level IS NOT NULL OR p.visibility='TEAM')`, projectID, userID).
		Scan(&project.ID, &project.TeamID, &project.Name, &project.Description, &project.ThumbnailURL, &project.Visibility, &project.CreatedBy, &project.AccessLevel, &project.CreatedAt, &project.UpdatedAt)
	return project, normalizeError(err)
}

func (r *PostgresRepository) Update(ctx context.Context, userID, projectID string, input model.UpdateProject) (model.Project, error) {
	current, err := r.Get(ctx, userID, projectID)
	if err != nil {
		return model.Project{}, err
	}
	if current.AccessLevel != model.ManagerAccess && current.AccessLevel != model.EditorAccess {
		return model.Project{}, model.ErrForbidden
	}
	var project model.Project
	err = r.Pool.QueryRow(ctx, `UPDATE projects p SET name=$1,description=$2,thumbnail_url=$3,visibility=$4,updated_at=now()
		WHERE p.id=$5 AND EXISTS (
			SELECT 1 FROM team_members tm LEFT JOIN project_permissions pp ON pp.project_id=p.id AND pp.user_id=tm.user_id
			WHERE tm.team_id=p.team_id AND tm.user_id=$6 AND (tm.role IN ('LEADER','DEPUTY') OR pp.access_level='EDITOR')
		)
		RETURNING p.id,p.team_id,p.name,p.description,p.thumbnail_url,p.visibility,p.created_by,p.updated_at`, input.Name, input.Description, input.ThumbnailURL, input.Visibility, projectID, userID).
		Scan(&project.ID, &project.TeamID, &project.Name, &project.Description, &project.ThumbnailURL, &project.Visibility, &project.CreatedBy, &project.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if _, lookupErr := r.Get(ctx, userID, projectID); lookupErr == nil {
				return model.Project{}, model.ErrForbidden
			}
		}
		return model.Project{}, normalizeError(err)
	}
	project.AccessLevel = current.AccessLevel
	return project, nil
}

func (r *PostgresRepository) Delete(ctx context.Context, userID, projectID string) error {
	tag, err := r.Pool.Exec(ctx, `DELETE FROM projects p WHERE p.id=$1 AND EXISTS (
		SELECT 1 FROM team_members tm WHERE tm.team_id=p.team_id AND tm.user_id=$2 AND tm.role IN ('LEADER','DEPUTY'))`, projectID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, lookupErr := r.Get(ctx, userID, projectID); lookupErr == nil {
			return model.ErrForbidden
		}
		return model.ErrNotFound
	}
	return nil
}

func (r *PostgresRepository) Members(ctx context.Context, userID, projectID string) ([]model.ProjectMember, error) {
	if _, err := r.Get(ctx, userID, projectID); err != nil {
		return nil, err
	}
	rows, err := r.Pool.Query(ctx, `SELECT tm.user_id,tm.nickname,COALESCE(u.avatar_url,''),tm.role,
		CASE WHEN tm.role IN ('LEADER','DEPUTY') THEN 'MANAGER' WHEN pp.access_level IS NOT NULL THEN pp.access_level WHEN p.visibility='TEAM' THEN 'VIEWER' ELSE '' END,pp.granted_at
		FROM projects p JOIN team_members tm ON tm.team_id=p.team_id JOIN users u ON u.id=tm.user_id
		LEFT JOIN project_permissions pp ON pp.project_id=p.id AND pp.user_id=tm.user_id
		WHERE p.id=$1 AND (tm.role IN ('LEADER','DEPUTY') OR pp.access_level IS NOT NULL OR p.visibility='TEAM')
		ORDER BY CASE tm.role WHEN 'LEADER' THEN 0 WHEN 'DEPUTY' THEN 1 ELSE 2 END,tm.joined_at,tm.user_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := make([]model.ProjectMember, 0)
	for rows.Next() {
		var member model.ProjectMember
		if err := rows.Scan(&member.UserID, &member.Nickname, &member.AvatarURL, &member.TeamRole, &member.AccessLevel, &member.GrantedAt); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (r *PostgresRepository) Grant(ctx context.Context, actorID, projectID, targetID string, level model.AccessLevel) error {
	if level != model.ViewerAccess && level != model.EditorAccess {
		return model.ErrInvalid
	}
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var teamID string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM projects WHERE id=$1`, projectID).Scan(&teamID); err != nil {
		return normalizeError(err)
	}
	if err = r.requireManagerTx(ctx, tx, actorID, teamID); err != nil {
		return err
	}
	var targetRole string
	if err = tx.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, targetID).Scan(&targetRole); err != nil {
		return normalizeError(err)
	}
	if targetRole == "LEADER" || targetRole == "DEPUTY" {
		return model.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO project_permissions(project_id,user_id,access_level,granted_by)
		VALUES($1,$2,$3,$4) ON CONFLICT(project_id,user_id) DO UPDATE SET access_level=EXCLUDED.access_level,granted_by=EXCLUDED.granted_by,granted_at=now()`, projectID, targetID, level, actorID); err != nil {
		return normalizeError(err)
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) Revoke(ctx context.Context, actorID, projectID, targetID string) error {
	var teamID string
	if err := r.Pool.QueryRow(ctx, `SELECT team_id FROM projects WHERE id=$1`, projectID).Scan(&teamID); err != nil {
		return normalizeError(err)
	}
	if err := r.requireManager(ctx, actorID, teamID); err != nil {
		return err
	}
	tag, err := r.Pool.Exec(ctx, `DELETE FROM project_permissions WHERE project_id=$1 AND user_id=$2`, projectID, targetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (r *PostgresRepository) RequestAccess(ctx context.Context, userID, projectID string, level model.AccessLevel, message string) (model.AccessRequest, error) {
	if level != model.ViewerAccess && level != model.EditorAccess {
		return model.AccessRequest{}, model.ErrInvalid
	}
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return model.AccessRequest{}, err
	}
	defer tx.Rollback(ctx)
	var teamRole string
	if err = tx.QueryRow(ctx, `SELECT tm.role FROM projects p JOIN team_members tm ON tm.team_id=p.team_id
		WHERE p.id=$1 AND tm.user_id=$2 FOR UPDATE OF tm`, projectID, userID).Scan(&teamRole); err != nil {
		return model.AccessRequest{}, normalizeError(err)
	}
	if teamRole == "LEADER" || teamRole == "DEPUTY" {
		return model.AccessRequest{}, model.ErrConflict
	}
	var request model.AccessRequest
	err = tx.QueryRow(ctx, `INSERT INTO project_access_requests(id,project_id,user_id,access_level,message)
		SELECT gen_random_uuid(),p.id,$1,$2,$3 FROM projects p
		WHERE p.id=$4 AND (NOT EXISTS(SELECT 1 FROM project_permissions pp WHERE pp.project_id=p.id AND pp.user_id=$1)
			OR ($2='EDITOR' AND EXISTS(SELECT 1 FROM project_permissions pp WHERE pp.project_id=p.id AND pp.user_id=$1 AND pp.access_level='VIEWER')))
		AND NOT EXISTS(SELECT 1 FROM team_members tm WHERE tm.team_id=p.team_id AND tm.user_id=$1 AND tm.role IN ('LEADER','DEPUTY'))
		AND (p.visibility='SELECTED' OR $2='EDITOR')
		ON CONFLICT(project_id,user_id) DO UPDATE SET access_level=EXCLUDED.access_level,message=EXCLUDED.message,status='PENDING',reviewed_by=NULL,created_at=now(),reviewed_at=NULL
		WHERE project_access_requests.status IN ('REJECTED','ACCEPTED')
		RETURNING id,project_id,user_id,access_level,message,status,created_at`, userID, level, message, projectID).
		Scan(&request.ID, &request.ProjectID, &request.UserID, &request.AccessLevel, &request.Message, &request.Status, &request.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.AccessRequest{}, model.ErrConflict
		}
		return model.AccessRequest{}, normalizeError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return model.AccessRequest{}, normalizeError(err)
	}
	return request, nil
}

func (r *PostgresRepository) AccessRequests(ctx context.Context, actorID, teamID string) ([]model.AccessRequest, error) {
	if err := r.requireManager(ctx, actorID, teamID); err != nil {
		return nil, err
	}
	rows, err := r.Pool.Query(ctx, `SELECT ar.id,ar.project_id,ar.user_id,u.nickname,ar.access_level,ar.message,ar.status,ar.created_at
		FROM project_access_requests ar JOIN projects p ON p.id=ar.project_id JOIN users u ON u.id=ar.user_id
		WHERE p.team_id=$1 AND ar.status='PENDING' ORDER BY ar.created_at,ar.id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := make([]model.AccessRequest, 0)
	for rows.Next() {
		var request model.AccessRequest
		if err := rows.Scan(&request.ID, &request.ProjectID, &request.UserID, &request.Nickname, &request.AccessLevel, &request.Message, &request.Status, &request.CreatedAt); err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (r *PostgresRepository) ReviewAccess(ctx context.Context, actorID, teamID, requestID string, accept bool) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManager(ctx, tx, actorID, teamID); err != nil {
		return err
	}
	var projectID, userID string
	var level model.AccessLevel
	var status model.RequestStatus
	err = tx.QueryRow(ctx, `SELECT ar.project_id,ar.user_id,ar.access_level,ar.status FROM project_access_requests ar
		JOIN projects p ON p.id=ar.project_id WHERE ar.id=$1 AND p.team_id=$2`, requestID, teamID).Scan(&projectID, &userID, &level, &status)
	if err != nil {
		return normalizeError(err)
	}
	if status != model.PendingStatus {
		return model.ErrConflict
	}
	newStatus := model.RejectedStatus
	if accept {
		var memberID string
		if err = tx.QueryRow(ctx, `SELECT tm.user_id FROM team_members tm JOIN projects p ON p.team_id=tm.team_id
			WHERE p.id=$1 AND tm.user_id=$2 AND tm.role='MEMBER' FOR UPDATE OF tm`, projectID, userID).Scan(&memberID); err != nil {
			return model.ErrConflict
		}
	}
	if err = tx.QueryRow(ctx, `SELECT status FROM project_access_requests WHERE id=$1 AND project_id=$2 FOR UPDATE`, requestID, projectID).Scan(&status); err != nil {
		return normalizeError(err)
	}
	if status != model.PendingStatus {
		return model.ErrConflict
	}
	if accept {
		newStatus = model.AcceptedStatus
		if _, err := tx.Exec(ctx, `INSERT INTO project_permissions(project_id,user_id,access_level,granted_by) VALUES($1,$2,$3,$4)
			ON CONFLICT(project_id,user_id) DO UPDATE SET access_level=EXCLUDED.access_level,granted_by=EXCLUDED.granted_by,granted_at=now()`, projectID, userID, level, actorID); err != nil {
			return normalizeError(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE project_access_requests SET status=$1,reviewed_by=$2,reviewed_at=now() WHERE id=$3`, newStatus, actorID, requestID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) RequestDeletion(ctx context.Context, userID, projectID, message string) (model.DeleteRequest, error) {
	if _, err := r.teamRoleForProject(ctx, userID, projectID); err != nil {
		return model.DeleteRequest{}, err
	}
	var request model.DeleteRequest
	err := r.Pool.QueryRow(ctx, `INSERT INTO project_delete_requests(id,project_id,requested_by,message)
		VALUES(gen_random_uuid(),$1,$2,$3) RETURNING id,project_id,requested_by,message,status,created_at`, projectID, userID, message).
		Scan(&request.ID, &request.ProjectID, &request.UserID, &request.Message, &request.Status, &request.CreatedAt)
	return request, normalizeError(err)
}

func (r *PostgresRepository) DeleteRequests(ctx context.Context, actorID, teamID string) ([]model.DeleteRequest, error) {
	if err := r.requireManager(ctx, actorID, teamID); err != nil {
		return nil, err
	}
	rows, err := r.Pool.Query(ctx, `SELECT dr.id,dr.project_id,dr.requested_by,u.nickname,dr.message,dr.status,dr.created_at
		FROM project_delete_requests dr JOIN projects p ON p.id=dr.project_id JOIN users u ON u.id=dr.requested_by
		WHERE p.team_id=$1 AND dr.status='PENDING' ORDER BY dr.created_at,dr.id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := make([]model.DeleteRequest, 0)
	for rows.Next() {
		var request model.DeleteRequest
		if err := rows.Scan(&request.ID, &request.ProjectID, &request.UserID, &request.Nickname, &request.Message, &request.Status, &request.CreatedAt); err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (r *PostgresRepository) ReviewDeletion(ctx context.Context, actorID, teamID, requestID string, accept bool) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireManager(ctx, tx, actorID, teamID); err != nil {
		return err
	}
	var projectID string
	var status model.RequestStatus
	err = tx.QueryRow(ctx, `SELECT dr.project_id,dr.status FROM project_delete_requests dr JOIN projects p ON p.id=dr.project_id
		WHERE dr.id=$1 AND p.team_id=$2 FOR UPDATE OF dr`, requestID, teamID).Scan(&projectID, &status)
	if err != nil {
		return normalizeError(err)
	}
	if status != model.PendingStatus {
		return model.ErrConflict
	}
	if accept {
		if _, err = tx.Exec(ctx, `DELETE FROM projects WHERE id=$1`, projectID); err != nil {
			return err
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE project_delete_requests SET status='REJECTED',reviewed_by=$1,reviewed_at=now() WHERE id=$2`, actorID, requestID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) teamRole(ctx context.Context, userID, teamID string) (string, error) {
	var role string
	err := r.Pool.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2`, teamID, userID).Scan(&role)
	return role, normalizeError(err)
}

func (r *PostgresRepository) teamRoleForProject(ctx context.Context, userID, projectID string) (string, error) {
	var role string
	err := r.Pool.QueryRow(ctx, `SELECT tm.role FROM projects p JOIN team_members tm ON tm.team_id=p.team_id WHERE p.id=$1 AND tm.user_id=$2`, projectID, userID).Scan(&role)
	return role, normalizeError(err)
}

func (r *PostgresRepository) requireManager(ctx context.Context, userID, teamID string) error {
	role, err := r.teamRole(ctx, userID, teamID)
	if err != nil {
		return err
	}
	if role != "LEADER" && role != "DEPUTY" {
		return model.ErrForbidden
	}
	return nil
}

func (r *PostgresRepository) requireManagerTx(ctx context.Context, tx pgx.Tx, userID, teamID string) error {
	var role string
	err := tx.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2 FOR UPDATE`, teamID, userID).Scan(&role)
	if err != nil {
		return normalizeError(err)
	}
	if role != "LEADER" && role != "DEPUTY" {
		return model.ErrForbidden
	}
	return nil
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func requireManager(ctx context.Context, query queryRower, userID, teamID string) error {
	var role string
	err := query.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2`, teamID, userID).Scan(&role)
	if err != nil {
		return normalizeError(err)
	}
	if role != "LEADER" && role != "DEPUTY" {
		return model.ErrForbidden
	}
	return nil
}
