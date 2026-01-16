-- down migration
ALTER TABLE users DROP COLUMN email_verified;
ALTER TABLE users DROP COLUMN verification_token;
ALTER TABLE users DROP COLUMN verification_token_expires_at;