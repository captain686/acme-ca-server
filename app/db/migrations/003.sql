
-- Support multiple challenges and types
ALTER TABLE challenges ADD COLUMN type TEXT NOT NULL DEFAULT 'http-01';
ALTER TABLE challenges DROP CONSTRAINT IF EXISTS challenges_authz_id_key;

-- Support revocation reasons
ALTER TABLE certificates ADD COLUMN revocation_reason INTEGER DEFAULT NULL;

-- Support External Account Binding (EAB)
CREATE TABLE eab_keys (
    id TEXT PRIMARY KEY,
    hmac_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    account_id RANDOM_ID REFERENCES accounts(id) DEFAULT NULL
);

ALTER TABLE accounts ADD COLUMN eab_key_id TEXT REFERENCES eab_keys(id) DEFAULT NULL;

-- Add new error types to acme_error_type enum
-- Note: PostgreSQL doesn't support adding to enum in transaction easily in some versions,
-- but we can use ALTER TYPE ... ADD VALUE if needed.
-- For simplicity in this migration, let's assume we might need to handle it or use TEXT if it becomes an issue.
-- However, standard ACME errors are well-defined.
ALTER TYPE acme_error_type ADD VALUE IF NOT EXISTS 'externalAccountRequired';
ALTER TYPE acme_error_type ADD VALUE IF NOT EXISTS 'accountDoesNotExist';
ALTER TYPE acme_error_type ADD VALUE IF NOT EXISTS 'incorrectThreshold';
