# Authorization Server (Spring Authorization Server)

Spring Authorization Server 기반의 OAuth 2.1 / OIDC 토큰 발급 서버 예제입니다. 
Authorization Code, Refresh Token, Client Credentials 그랜트 타입을 지원하며, 
토큰 무효화(revocation), 토큰 유효성 검사(introspection), JWK 공개 키 제공(jwks) 엔드포인트를 포함합니다.

OAuth 2.0 -> 2.1 버전업이 된 핵심계기
1. OAuth 2.0의 복잡성 → OAuth 2.1 단순화
10개 넘는 Grant Type과 옵션이 있었지만 불필요 기능들이 폐기되었습니다.
그 중 `Implicit Grant`와 `Password Grant` 제거되면서 
프론트에서 Access Token을 클라이언트로 직접 받을 수 없게되고 서버가 JWT를 만들어주는 패턴이 일반화 되었습니다.

2. Stateful -> Stateless
Opaque Token 랜덤 문자열을 검증하려면
```aiignore
    Client → Resource Server → Authorization Server(introspection)
```
핸덤 문자열이기때문에 사용자정보,권한, 만료시간, 발급 정보 등 아무것도 알수 없다
이로인해 서버에 전달되어 검증이 필요하며 서비스가 많으면 병목이 발생한다.
JWT는 자체 서명이 포함되어있어서 리소스 서버가 토큰 단독 검증이 가능하다
*하지만 보안이 중요한 곳에서는 여전히 Opaque Token이 사용된다.

3. 비용 절감
세션 기반/opaque token 기반은 서버가 토큰 상태를 저장해야 하므로
OAuth 2.0 내장되어있는 RedisTokenStore를 사용한다.
Redis 같은 세션 저장소 구축 비용이 발생하고 저장소 장애로 인한 전체 로그인 서비스 중단을 막기 위하여 
안정적인 서비스를 위해 클러스터링을 하는 등 유지 보수 비용 또한 증가한다.

4. 

## 주요 기능
- OAuth 2.1 Authorization Code 그랜트로 액세스 토큰/리프레시 토큰 발급
- Client Credentials 그랜트 지원
- Refresh Token 재발급 지원
- JWKS 공개 키 제공(`/oauth2/jwks`)
- 토큰 무효화(`/oauth2/revoke`)
- 토큰 유효성 검사(`/oauth2/introspect`)

## 기술 스택
- Java 17+ (권장)
- Spring Boot 3.x
- Spring Authorization Server
- MS SQL (`docker-compose.yml` 참고) (스키마는 `src/main/resources/schema.sql` 참고)

3) 기본 포트 및 콜백
- 서버 포트: `http://localhost:9090`
- 콜백 URL(예시): `http://localhost:9090/auth/callback`

애플리케이션 설정은 `src\main\resources\application.yml`에서 변경할 수 있습니다.

## 엔드포인트 요약 및 예제

아래 예제는 기본 포트(9090) 기준입니다. 필요 시 `client_id`, `redirect_uri` 등을 환경에 맞게 수정하세요.

### 1) 로그인 화면 / 인가 코드 요청 (Authorization Code)
```
GET http://localhost:9090/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9090/auth/callback&scope=openid%20profile%20email
```
또는 cURL:
```
curl -X GET "http://localhost:9090/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9090/auth/callback&scope=openid%20profile%20email"
```

브라우저로 접근하면 로그인 페이지로 리다이렉트되고 인증 성공 시 `redirect_uri`로 `code`가 전달됩니다.

### 2) 토큰 발급 (Authorization Code → Access/Refresh Token)
```
curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code={AUTH_CODE}" \
  -d "redirect_uri=http://localhost:9090/auth/callback" \
  -d "user_id={user_id}" \
  -d "password={password}"
```

응답은 `access_token`, `refresh_token`, `expires_in`, `scope`, `token_type` 등을 포함합니다.

### 3) Refresh Token 재발급
```
curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token={refresh_token}"
```

### 4) Client Credentials 토큰 발급
```
curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

### 5) JWK 공개 키 목록
```
curl -X GET http://localhost:9090/oauth2/jwks
```

### 6) 토큰 무효화 (Revocation)
```
curl -X POST http://localhost:9090/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d token={access_token OR refresh_token}
```

### 7) 토큰 유효성 검사 (Introspection)
```
curl -X POST http://localhost:9090/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d token={access_token OR refresh_token}
```

## 이전 정리
* 로그인화면 URL
  `curl -X GET "http://localhost:9090/oauth2/authorize
  ?response_type=code
  &client_id=test-client
  &redirect_uri=http://localhost:9090/auth/callback&scope=openid%20profile%20email"`
  `(GET http://local/host:9090/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9090/auth/callback&scope=openid profile email)`

* Token 발급
  `curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code={AUTH_CODE}" \
  -d "redirect_uri=http://localhost:9090/auth/callback" \
  -d "user_id={user_id}" \
  -d "password={password}"`

* refresh_token 재발급 (옵션필요)
  `curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token={refresh_token}"`

* client_credentials Token 발급
  `curl -X POST http://localhost:9090/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"`

* JWT 정보
  `curl -X GET http://localhost:9090/oauth2/jwks`

* 토큰 무효화
  `curl -X POST http://localhost:9090/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d token={access_token OR refresh_token}`

* 토큰 유효성 검사
  `curl -X POST http://localhost:9090/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d token={access_token OR refresh_token}`
