-- 일반 사용자 (password: password123)
INSERT INTO users (id, username, password, email, role, enabled) VALUES
    (1, 'user', '$2a$10$3NIoIpLCHktbod4JIUWGKOQ6wJCEyBT.EymugQejf25KYLRUcLcGe', 'user@example.com', 'USER', true);

-- 관리자 (password: password123)
INSERT INTO users (id, username, password, email, role, enabled) VALUES
    (2, 'admin', '$2a$10$3NIoIpLCHktbod4JIUWGKOQ6wJCEyBT.EymugQejf25KYLRUcLcGe', 'admin@example.com', 'ADMIN', true);

-- 매니저 (password: password123)
INSERT INTO users (id, username, password, email, role, enabled) VALUES
    (3, 'manager', '$2a$10$3NIoIpLCHktbod4JIUWGKOQ6wJCEyBT.EymugQejf25KYLRUcLcGe', 'manager@example.com', 'MANAGER', true);