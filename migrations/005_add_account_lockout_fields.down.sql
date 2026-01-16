-- down migration
ALTER TABLE users DROP COLUMN failed_attempts;
ALTER TABLE users DROP COLUMN locked_until;
ALTER TABLE users DROP COLUMN is_locked;