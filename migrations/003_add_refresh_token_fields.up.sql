-- up migration
ALTER TABLE users ADD COLUMN refresh_token VARCHAR(255);
ALTER TABLE users ADD COLUMN refresh_token_expires_at TIMESTAMP;