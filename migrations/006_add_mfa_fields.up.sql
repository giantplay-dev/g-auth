-- Add MFA fields to users table
ALTER TABLE users
ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL,
ADD COLUMN mfa_code VARCHAR(6),
ADD COLUMN mfa_code_expires_at TIMESTAMP;

-- Create index for MFA code lookups
CREATE INDEX idx_users_mfa_code ON users(mfa_code) WHERE mfa_code IS NOT NULL;
