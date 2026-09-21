# SceneSpect 인증 서버

Go/Gin 기반 인증·인가 API입니다. 완료되지 않은 회원가입은 Redis TTL 상태로 관리하고, 회원·약관 동의·Refresh Token 해시는 PostgreSQL에 저장합니다.

## 로컬 실행

```sh
cp .env.example .env
# .env의 JWT_SECRET, CODE_SECRET를 각각 openssl rand -base64 32 값으로 교체
docker compose up --build
```

`app`, `postgres`, `redis`가 모두 healthy 상태가 되면 `http://localhost:8080/healthz`에서 상태를 확인할 수 있습니다. 개발 모드의 이메일 인증 코드와 비밀번호 재설정 토큰은 app 로그에 출력됩니다. 운영에서는 SMTP와 `COOKIE_SECURE=true`, HTTPS Origin을 사용해야 합니다.

## 패키지 구조

책임별 `cmd` + `internal` 경계를 사용합니다. `cmd/api`는 조립과 서버 생명주기만 담당하고, 실제 유스케이스는 `service`가, HTTP 변환은 `handler`가 담당합니다.

```text
cmd/
├── api/main.go                 # 의존성 주입과 HTTP 서버 실행
└── migrate/main.go             # Goose migration 실행
internal/
├── cache/                      # 가입·인증코드·재설정·rate limit TTL 상태
├── config/config.go            # 환경변수 검증
├── database/postgres.go        # PostgreSQL pool 연결 확인
├── domain/                     # 사용자·약관·가입·토큰 타입과 오류
├── handler/                    # 요청 DTO와 응답·쿠키 처리
├── mailer/mailer.go            # SMTP/콘솔 메일 어댑터
├── middleware/auth.go          # Access Token 인증과 RBAC
├── repository/                 # PostgreSQL 사용자·약관·토큰 저장소
├── router/router.go            # 라우트와 미들웨어 조립
├── security/                   # JWT, bcrypt, 난수, 입력 검증
└── service/                    # 회원가입·로그인·계정 유스케이스
```

가입 중간 상태는 영속 회원이 아니므로 Redis에 TTL로 저장합니다. 이렇게 하면 미완료 가입을 PostgreSQL에서 별도 정리할 배치 없이 자동 만료시킬 수 있고, 인증코드·rate limit·비밀번호 재설정 토큰과 동일한 만료 정책으로 관리할 수 있습니다. 최종 회원·약관 동의·Refresh Token hash는 PostgreSQL에 저장합니다.

## 주요 API

| 단계 | 메서드 | 경로 |
| --- | --- | --- |
| 약관 조회 | GET | `/api/v1/auth/signup/terms` |
| 가입 이메일 시작 | POST | `/api/v1/auth/signup/start` |
| 비밀번호 설정 | POST | `/api/v1/auth/signup/password` |
| 인증코드 발송/확인 | POST | `/api/v1/auth/signup/email/send`, `/api/v1/auth/signup/email/verify` |
| 약관 동의 및 가입 완료 | POST | `/api/v1/auth/signup/terms` |
| 로그인/토큰 재발급/로그아웃 | POST | `/api/v1/auth/login`, `/api/v1/auth/token/refresh`, `/api/v1/auth/logout` |
| 내 정보/닉네임 | GET/PATCH | `/api/v1/me`, `/api/v1/me/nickname` |
| 비밀번호 찾기/재설정 | POST | `/api/v1/auth/password/forgot`, `/api/v1/auth/password/reset` |
| 계정 찾기 | POST | `/api/v1/auth/account/find` |

Access Token은 `Authorization: Bearer ...`로 전달하고, Refresh Token은 `HttpOnly; Secure; SameSite=Lax` 쿠키로만 전달합니다. Refresh Token 원문은 저장하지 않고 SHA-256 해시만 저장하며, 재발급 때마다 회전합니다. 폐기된 토큰이 다시 사용되면 같은 family 전체를 폐기합니다.

## 가입 요청 예시

```json
{
  "signupSessionId": "...",
  "consents": [
    {"termId":"00000000-0000-0000-0000-000000000001", "accepted":true},
    {"termId":"00000000-0000-0000-0000-000000000002", "accepted":true},
    {"termId":"00000000-0000-0000-0000-000000000003", "accepted":false}
  ]
}
```

## 설계 메모

- 기본 `username`과 `nickname`은 이메일의 `@` 앞부분에서 시작하고, 충돌 시 `-2`, `-3` suffix를 붙입니다. 가입 시 username은 고정되고 nickname만 변경됩니다.
- 인증코드는 6자리·5분 TTL이며 HMAC으로 Redis에 저장합니다. 발송 쿨다운, 시간당 발송 제한, 5회 실패 제한을 Redis Lua 스크립트로 원자 처리합니다.

## 검증

```sh
gofmt -w cmd internal migrations
go test ./...
go vet ./...
docker compose config
```

Docker 데몬이 실행 중이면 `docker compose up --build`로 실제 PostgreSQL, Redis, migration, healthcheck까지 확인할 수 있습니다.
