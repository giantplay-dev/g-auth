-- Remove MFA fields from users table
DROP INDEX IF EXISTS idx_users_mfa_code;

ALTER TABLE users
DROP COLUMN IF EXISTS mfa_enabled,
DROP COLUMN IF EXISTS mfa_code,
DROP COLUMN IF EXISTS mfa_code_expires_at;
