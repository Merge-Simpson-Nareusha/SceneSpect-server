# SceneSpect API 서버

Go와 Gin 기반의 SceneSpect API 서버입니다. 계정·세션, OAuth 로그인, 팀과 프로젝트 관리, 프로필 및 화면 설정, 이미지 업로드 API를 제공합니다. PostgreSQL은 영속 데이터, Redis는 가입·인증·OAuth 임시 상태에 사용합니다.

## 로컬 실행

```sh
cp .env.example .env
# .env의 JWT_SECRET, CODE_SECRET를 서로 다른 `openssl rand -base64 32` 값으로 교체
docker compose up --build
```

서비스가 준비되면 다음 주소를 사용할 수 있습니다.

- 상태 확인: `http://localhost:8080/healthz`
- Swagger UI: `http://localhost:8080/swagger`
- OpenAPI 문서: `http://localhost:8080/openapi.yaml`

Swagger UI는 CDN에서 정적 리소스를 가져오므로 브라우저가 인터넷에 연결되어 있어야 합니다. OpenAPI YAML은 서버에 포함되어 제공됩니다. 개발 모드에서 이메일 인증 코드와 비밀번호 재설정 토큰은 앱 로그에 출력됩니다. 운영에서는 SMTP, `COOKIE_SECURE=true`, HTTPS `WEB_ORIGIN`과 `API_BASE_URL`을 사용해야 합니다.

## 주요 API

인증이 필요한 요청은 `Authorization: Bearer <accessToken>` 헤더를 사용합니다. Refresh Token은 `HttpOnly` 쿠키로만 전달됩니다.

| 기능 | 메서드 | 경로 |
| --- | --- | --- |
| 회원가입 약관 조회 및 완료 | GET, POST | `/api/v1/auth/signup/terms` |
| 이메일 가입·인증 | POST | `/api/v1/auth/signup/start`, `/password`, `/email/send`, `/email/verify` |
| 로그인·토큰 갱신·로그아웃 | POST | `/api/v1/auth/login`, `/token/refresh`, `/logout` |
| 비밀번호 재설정·계정 찾기 | POST | `/api/v1/auth/password/forgot`, `/password/reset`, `/account/find` |
| 내 계정·프로필 조회 | GET | `/api/v1/auth/me` |
| 닉네임·프로필·화면 테마·비밀번호 변경 | PATCH, POST | `/api/v1/auth/me/nickname`, `/me/profile`, `/me/display-theme`, `/me/password` |
| OAuth 로그인·계정 연결 | GET, POST | `/api/v1/auth/oauth/{provider}/start`, `/callback`, `/link/start` |
| OAuth 이메일 확인·가입 완료 | POST | `/api/v1/auth/oauth/complete/email/send`, `/email/verify`, `/complete` |
| 팀 목록·생성·정렬 | GET, POST, PUT | `/api/v1/teams`, `/api/v1/teams/order` |
| 팀 설정·삭제·멤버 관리 | GET, PATCH, DELETE | `/api/v1/teams/{teamId}` 및 하위 `/members` 경로 |
| 팀 가입 요청·검토 | POST, GET, PATCH | `/api/v1/teams/join-requests`, `/api/v1/teams/{teamId}/join-requests` |
| 팀 프로젝트 목록·생성 | GET, POST | `/api/v1/teams/{teamId}/projects` |
| 프로젝트 조회·수정·삭제 | GET, PATCH, DELETE | `/api/v1/projects/{projectId}` |
| 프로젝트 권한·접근 요청 | GET, PUT, DELETE, POST | `/api/v1/projects/{projectId}/members`, `/permissions/{userId}`, `/access-requests` |
| 프로젝트 삭제 요청·검토 | POST, GET, PATCH | `/api/v1/projects/{projectId}/delete-requests`, `/api/v1/teams/{teamId}/project-delete-requests` |
| 이미지 업로드·조회 | POST, GET | `/api/v1/media/images`, `/media/{filename}` |

세부 요청·응답 형식과 상태 코드는 Swagger UI에서 확인할 수 있습니다.

프로젝트 공개 범위는 `TEAM`(팀원 전체 읽기) 또는 `SELECTED`(선택된 팀원만 접근)로 설정합니다. 프로젝트 작성자와 팀장·부팀장은 프로젝트 관리 권한을 가집니다. `TEAM` 프로젝트에서 편집 권한이 필요한 팀원은 `EDITOR` 접근 신청을 제출할 수 있습니다.

## 계정 및 OAuth 설정

Google, Kakao, X, Apple OAuth는 선택적으로 사용할 수 있습니다. 사용할 공급자의 개발자 콘솔에 다음 콜백 주소를 등록하고 `.env`의 해당 값을 설정합니다.

| 공급자 | 콜백 주소 |
| --- | --- |
| Google | `{API_BASE_URL}/api/v1/auth/oauth/google/callback` |
| Kakao | `{API_BASE_URL}/api/v1/auth/oauth/kakao/callback` |
| X | `{API_BASE_URL}/api/v1/auth/oauth/x/callback` |
| Apple | `{API_BASE_URL}/api/v1/auth/oauth/apple/callback` (form_post) |

X 계정에서 이메일 주소를 제공하지 않으면 가입 과정에서 이메일 인증을 완료해야 합니다. OAuth 공급자 비밀 값은 저장소에 넣지 말고 환경변수로만 전달합니다. Apple은 `.p8` 개인 키를 Base64로 인코딩해 `OAUTH_APPLE_PRIVATE_KEY_B64`에 설정합니다.

Access Token은 짧은 만료 시간을 가지며, Refresh Token 원문 대신 해시를 저장하고 갱신마다 회전합니다. 재사용된 폐기 토큰이 감지되면 해당 토큰 계열을 폐기합니다.

## 이미지 저장

프로필·팀·프로젝트 이미지 업로드는 인증된 사용자가 `multipart/form-data`의 `file` 필드로 요청합니다. JPEG와 PNG 파일을 검증하고 메타데이터를 제거해 저장합니다. 업로드 응답의 `url`을 프로필 또는 팀·프로젝트 정보에 전달해 연결할 수 있습니다.

Docker Compose에서는 파일을 `/app/uploads`에 저장하고 `uploads` named volume에 보존합니다. 기본 업로드 크기 제한은 5 MiB이며 `MEDIA_MAX_IMAGE_BYTES`로 조정할 수 있습니다. 로컬 실행 환경에서는 `MEDIA_STORAGE_DIR` 경로를 사용합니다.

## 패키지 구조

```text
cmd/server/                    의존성 조립, 라우터, 서버 생명주기
cmd/migrate/                   Goose migration 실행
internal/domain/auth/          이메일 인증, OAuth, 계정·세션 처리
internal/domain/authorization/ 역할 기반 인가
internal/domain/media/         이미지 업로드·조회 HTTP 핸들러
internal/domain/project/       프로젝트·접근 권한·요청 흐름
internal/domain/team/          팀·멤버·가입 요청 흐름
internal/docs/                 내장 OpenAPI YAML과 Swagger UI
internal/global/config/        환경 변수 로드와 검증
internal/global/database/      PostgreSQL 및 Redis 연결·저장
internal/global/media/         로컬 이미지 파일 저장
internal/global/mailer/        SMTP 및 개발 콘솔 메일 발송
internal/global/security/      JWT, 비밀번호, 입력 검증
migrations/                    PostgreSQL 스키마 migration
```

## 검증

```sh
gofmt -w cmd internal
go build ./...
go vet ./...
go test ./...
docker compose config
```

Docker 데몬이 실행 중이면 `docker compose up --build`로 PostgreSQL, Redis, migration과 healthcheck까지 확인할 수 있습니다.
