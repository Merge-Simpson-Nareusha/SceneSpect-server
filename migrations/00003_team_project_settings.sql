-- +goose Up
ALTER TABLE users
    ADD COLUMN avatar_url TEXT,
    ADD COLUMN display_theme VARCHAR(10) NOT NULL DEFAULT 'SYSTEM'
        CHECK (display_theme IN ('LIGHT', 'DARK', 'SYSTEM'));

CREATE TABLE teams (
    id UUID PRIMARY KEY,
    name VARCHAR(80) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    youtube_url TEXT NOT NULL DEFAULT '',
    guideline TEXT NOT NULL DEFAULT '',
    avatar_url TEXT,
    join_code VARCHAR(16) NOT NULL UNIQUE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(name) BETWEEN 1 AND 80)
);
CREATE UNIQUE INDEX teams_name_lower_unique_idx ON teams (lower(name));

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nickname VARCHAR(50) NOT NULL,
    role VARCHAR(10) NOT NULL DEFAULT 'MEMBER'
        CHECK (role IN ('LEADER', 'DEPUTY', 'MEMBER')),
    warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
    can_create_projects BOOLEAN NOT NULL DEFAULT false,
    sort_order INTEGER NOT NULL DEFAULT 0,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
CREATE UNIQUE INDEX team_members_one_leader_idx
    ON team_members (team_id) WHERE role = 'LEADER';
CREATE UNIQUE INDEX team_members_one_deputy_idx
    ON team_members (team_id) WHERE role = 'DEPUTY';
CREATE INDEX team_members_user_sort_idx ON team_members (user_id, sort_order);

CREATE TABLE team_join_requests (
    id UUID PRIMARY KEY,
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nickname VARCHAR(50) NOT NULL,
    status VARCHAR(10) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED')),
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    UNIQUE (team_id, user_id)
);
CREATE INDEX team_join_requests_team_status_idx ON team_join_requests (team_id, status, created_at);

CREATE TABLE projects (
    id UUID PRIMARY KEY,
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    thumbnail_url TEXT,
    visibility VARCHAR(10) NOT NULL DEFAULT 'TEAM'
        CHECK (visibility IN ('TEAM', 'SELECTED')),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(name) BETWEEN 1 AND 100)
);
CREATE INDEX projects_team_created_idx ON projects (team_id, created_at DESC, id);
CREATE UNIQUE INDEX projects_team_name_lower_unique_idx ON projects (team_id, lower(name));

CREATE TABLE project_permissions (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_level VARCHAR(10) NOT NULL CHECK (access_level IN ('VIEWER', 'EDITOR')),
    granted_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX project_permissions_user_idx ON project_permissions (user_id, project_id);

CREATE TABLE project_access_requests (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_level VARCHAR(10) NOT NULL DEFAULT 'VIEWER'
        CHECK (access_level IN ('VIEWER', 'EDITOR')),
    message TEXT NOT NULL DEFAULT '',
    status VARCHAR(10) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED')),
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    UNIQUE (project_id, user_id)
);
CREATE INDEX project_access_requests_status_idx ON project_access_requests (project_id, status, created_at);

CREATE TABLE project_delete_requests (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message TEXT NOT NULL DEFAULT '',
    status VARCHAR(10) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED')),
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ
);
CREATE INDEX project_delete_requests_status_idx ON project_delete_requests (project_id, status, created_at);
CREATE UNIQUE INDEX project_delete_requests_one_pending_idx ON project_delete_requests(project_id) WHERE status='PENDING';

-- +goose Down
DROP TABLE project_delete_requests;
DROP TABLE project_access_requests;
DROP TABLE project_permissions;
DROP TABLE projects;
DROP TABLE team_join_requests;
DROP TABLE team_members;
DROP TABLE teams;
ALTER TABLE users DROP COLUMN display_theme, DROP COLUMN avatar_url;
