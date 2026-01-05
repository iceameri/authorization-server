CREATE TABLE oauth2_authorization
(
    id                            NVARCHAR(100)  NOT NULL,
    registered_client_id          NVARCHAR(100)  NOT NULL,
    principal_name                NVARCHAR(200)  NOT NULL,
    authorization_grant_type      NVARCHAR(100)  NOT NULL,
    authorized_scopes             NVARCHAR(1000) NULL,
    attributes                    NVARCHAR(MAX)  NULL,
    state                         NVARCHAR(500)  NULL,

    authorization_code_value      NVARCHAR(MAX)  NULL,
    authorization_code_issued_at  DATETIME       NULL,
    authorization_code_expires_at DATETIME       NULL,
    authorization_code_metadata   NVARCHAR(MAX)  NULL,

    access_token_value            NVARCHAR(MAX)  NULL,
    access_token_issued_at        DATETIME       NULL,
    access_token_expires_at       DATETIME       NULL,
    access_token_metadata         NVARCHAR(MAX)  NULL,
    access_token_type             NVARCHAR(100)  NULL,
    access_token_scopes           NVARCHAR(1000) NULL,

    oidc_id_token_value           NVARCHAR(MAX)  NULL,
    oidc_id_token_issued_at       DATETIME       NULL,
    oidc_id_token_expires_at      DATETIME       NULL,
    oidc_id_token_metadata        NVARCHAR(MAX)  NULL,

    refresh_token_value           NVARCHAR(MAX)  NULL,
    refresh_token_issued_at       DATETIME       NULL,
    refresh_token_expires_at      DATETIME       NULL,
    refresh_token_metadata        NVARCHAR(MAX)  NULL,

    user_code_value               NVARCHAR(MAX)  NULL,
    user_code_issued_at           DATETIME       NULL,
    user_code_expires_at          DATETIME       NULL,
    user_code_metadata            NVARCHAR(MAX)  NULL,

    device_code_value             NVARCHAR(MAX)  NULL,
    device_code_issued_at         DATETIME       NULL,
    device_code_expires_at        DATETIME       NULL,
    device_code_metadata          NVARCHAR(MAX)  NULL,

    CONSTRAINT PK_oauth2_authorization PRIMARY KEY (id)
);

CREATE INDEX idx_01_registered_client_id
    ON oauth2_authorization (registered_client_id);

CREATE INDEX idx_02_principal_name
    ON oauth2_authorization (principal_name);

CREATE INDEX idx_03_state
    ON oauth2_authorization (state);

CREATE TABLE oauth2_authorization_consent
(
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name       VARCHAR(200)  NOT NULL,
    authorities          NVARCHAR(MAX) NOT NULL,
    CONSTRAINT PK_oauth2_authorization_consent PRIMARY KEY (registered_client_id, principal_name),
);

CREATE TABLE oauth2_registered_client
(
    id                            VARCHAR(100) NOT NULL,
    client_id                     VARCHAR(100) NOT NULL,
    client_id_issued_at           DATETIME     NOT NULL,
    client_secret                 VARCHAR(200),
    client_secret_expires_at      DATETIME,
    client_name                   VARCHAR(200) NOT NULL,
    client_authentication_methods VARCHAR(MAX) NOT NULL,
    authorization_grant_types     VARCHAR(MAX) NOT NULL,
    redirect_uris                 VARCHAR(MAX),
    post_logout_redirect_uris     VARCHAR(MAX),
    scopes                        VARCHAR(MAX) NOT NULL,
    client_settings               VARCHAR(MAX) NOT NULL,
    token_settings                VARCHAR(MAX) NOT NULL,
    CONSTRAINT [PK_oauth2_registered_client] PRIMARY KEY CLUSTERED (id ASC),
    CONSTRAINT [UK_oauth2_registered_client_01] UNIQUE NONCLUSTERED (client_id ASC)
);

INSERT INTO oauth2_registered_client (id,
                                      client_id,
                                      client_id_issued_at,
                                      client_secret,
                                      client_name,
                                      client_authentication_methods,
                                      authorization_grant_types,
                                      redirect_uris,
                                      scopes,
                                      client_settings,
                                      token_settings)
VALUES ('1',
        'test-client',
        GETDATE(),
        '{bcrypt}$2a$10$vNyUhWG2.Gd70U4zW9runOVnKaNmY9/DxcAdLweXqHch48eEYdO7i', -- P@$$w0rd1!
        'test',
        'client_secret_basic,client_secret_post,client_secret_jwt,private_key_jwt',
        'authorization_code,refresh_token,client_credentials,urn:ietf:params:oauth:grant-type:device_code',
        'http://localhost:9090/oauth2/authorize,http://localhost:9090/oauth2/token,http://localhost:9090/auth/authorized',
        'openid,profile,email',
        '{"@class":"java.util.Collections$UnmodifiableMap",
            "settings.client.require-proof-key":false,
            "settings.client.require-authorization-consent":false
            }',
        '{
            "@class": "java.util.Collections$UnmodifiableMap",
            "settings.token.authorization-code-time-to-live": ["java.time.Duration", 300.000000000],
            "settings.token.access-token-time-to-live": ["java.time.Duration", 1800.000000000],
            "settings.token.refresh-token-time-to-live": ["java.time.Duration", 86400.000000000],
            "settings.token.reuse-refresh-tokens": ["java.lang.Boolean", false],
            "settings.token.device-code-time-to-live": ["java.time.Duration", 300.000000000]
            }'),
       ('2',
        'opaque-client',
        GETDATE(),
        '{bcrypt}$2a$10$vNyUhWG2.Gd70U4zW9runOVnKaNmY9/DxcAdLweXqHch48eEYdO7i', -- 비번: P@$$w0rd1!
        'opaque-client-service',
        'client_secret_basic,client_secret_post',
        'authorization_code,refresh_token,client_credentials',
        'http://localhost:9090/oauth2/authorize,http://localhost:9090/oauth2/token,http://localhost:9090/auth/authorized',
        'openid,profile,email',
        '{"@class":"java.util.Collections$UnmodifiableMap",
          "settings.client.require-proof-key":false,
          "settings.client.require-authorization-consent":false
         }',
           -- ▼ token_settings: access token 형식 = opaque
        '{
            "@class": "java.util.Collections$UnmodifiableMap",
            "settings.token.authorization-code-time-to-live": ["java.time.Duration", 300.000000000],
            "settings.token.access-token-time-to-live": ["java.time.Duration", 1800.000000000],
            "settings.token.refresh-token-time-to-live": ["java.time.Duration", 86400.000000000],
            "settings.token.reuse-refresh-tokens": ["java.lang.Boolean", false],
            "settings.token.device-code-time-to-live": ["java.time.Duration", 300.000000000],
            "settings.token.access-token-format": ["org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat", "reference"]
         }');


CREATE TABLE user_details
(
    user_id                 VARCHAR(255)  NOT NULL,                   -- 로그인 ID (예: 이메일, 아이디)
    password                VARCHAR(255)  NOT NULL,                   -- 암호화된 비밀번호
    enabled                 BIT           NOT NULL DEFAULT 1,         -- 계정 활성 여부 (1 = 활성, 0 = 비활성)
    account_non_expired     BIT           NOT NULL DEFAULT 1,         -- 계정 만료 여부
    credentials_non_expired BIT           NOT NULL DEFAULT 1,         -- 비밀번호 만료 여부
    account_non_locked      BIT           NOT NULL DEFAULT 1,         -- 계정 잠금 여부
    created_at              DATETIME      NOT NULL DEFAULT GETDATE(), -- 생성일시
    updated_at              DATETIME      NULL,                       -- 수정일시
    email                   NVARCHAR(320) NULL,                       -- 이메일
    phone                   NVARCHAR(50)  NULL,                       -- 전화번호
    CONSTRAINT [PK_user_details] PRIMARY KEY CLUSTERED (user_id ASC),
    CONSTRAINT [UK_user_details_01] UNIQUE NONCLUSTERED (email ASC, phone ASC)
);

INSERT INTO user_details ( user_id
                         , password
                         , enabled
                         , account_non_expired
                         , credentials_non_expired
                         , account_non_locked
                         , created_at
                         , updated_at
                         , email
                         , phone)
VALUES ('admin',
        '{noop}1234qwer!!',
        1,
        1,
        1,
        1,
        '2025-05-27 16:34:13',
        NULL,
        N'admin@admin.co.kr',
        N'01011112222'),
       ('qwer',
        '{noop}1234',
        1,
        1,
        1,
        1,
        CONVERT(DATE, '2025-05-27 16:39:11.6866667'),
        NULL,
        N'qwer@qwer.co.kr',
        N'01011112222');

CREATE TABLE roles
(
    role_id     BIGINT IDENTITY (1,1) NOT NULL,
    role_name   VARCHAR(50)           NOT NULL, -- USER, ADMIN, OPERATOR 등
    description NVARCHAR(255)         NULL,
    created_at  DATETIME              NOT NULL DEFAULT GETDATE(),
    CONSTRAINT PK_roles PRIMARY KEY CLUSTERED (role_id),
    CONSTRAINT UK_roles_name UNIQUE (role_name)
);
INSERT INTO roles (role_name, description)
VALUES ('USER', N'일반 사용자'),
       ('ADMIN', N'관리자'),
       ('OPERATOR', N'운영자');

CREATE TABLE user_roles
(
    user_id     VARCHAR(255) NOT NULL,
    role_id     BIGINT       NOT NULL,
    assigned_at DATETIME     NOT NULL DEFAULT GETDATE(),
    CONSTRAINT PK_user_roles PRIMARY KEY CLUSTERED (user_id, role_id),
);
INSERT INTO user_roles (user_id, role_id)
VALUES ('admin@admin.com', 1); -- USER

CREATE TABLE user_identities
(
    identity_id BIGINT IDENTITY (1,1) NOT NULL,
    user_id     VARCHAR(255)          NOT NULL, -- user_details.user_id
    provider    VARCHAR(50)           NOT NULL, -- google, kakao, github 등
    provider_id VARCHAR(255)          NOT NULL, -- external sub / id
    created_at  DATETIME              NOT NULL DEFAULT GETDATE(),
    CONSTRAINT PK_user_identities PRIMARY KEY CLUSTERED (identity_id),
    CONSTRAINT UK_user_identities_provider_id UNIQUE (provider, provider_id)
);


USE resource;
GO;

