-- 일반 사용자 (password: password123)
INSERT INTO users (id, username, password, email, role, enabled) VALUES
    (1, 'user', '$2a$10$3NIoIpLCHktbod4JIUWGKOQ6wJCEyBT.EymugQejf25KYLRUcLcGe', 'user@example.com', 'USER', true);

-- 관리자 (password: password123)
INSERT INTO users (id, username, password, email, role, enabled) VALUES
    (2, 'admin', '$2a$10$3NIoIpLCHktbod4JIUWGKOQ6wJCEyBT.EymugQejf25KYLRUcLcGe', 'admin@example.com', 'ADMIN', true);

-- 매니저 (password: password123)
INSERT INTO users (id, username, password, email, role, enabled) VALUES
    (3, 'manager', '$2a$10$3NIoIpLCHktbod4JIUWGKOQ6wJCEyBT.EymugQejf25KYLRUcLcGe', 'manager@example.com', 'MANAGER', true);

-- Remember-Me 토큰 저장 테이블
CREATE TABLE IF NOT EXISTS persistent_logins (
    -- 시리즈 식별자 (Primary Key)
    -- UUID 형식, 로그인 세션마다 고유
                                                 series VARCHAR(64) PRIMARY KEY,

    -- 사용자명
    -- User 테이블의 username과 연결
                                                 username VARCHAR(64) NOT NULL,

    -- 인증 토큰
    -- 매번 변경되는 토큰, SecureRandom 생성
                                                 token VARCHAR(64) NOT NULL,

    -- 마지막 사용 시간
    -- 토큰이 마지막으로 사용된 시각
    -- 오래된 토큰 정리에 사용
                                                 last_used TIMESTAMP NOT NULL
);

-- 성능 최적화: username으로 조회 가능
-- 사용자의 모든 Remember-Me 토큰 조회 시 사용
CREATE INDEX idx_persistent_logins_username
    ON persistent_logins(username);