CREATE TABLE Authorization_code_pending_request(
    code VARCHAR(8) PRIMARY KEY,
    client_id VARCHAR(36) NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method VARCHAR(15),
    scopes JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    sub VARCHAR(36) NOT NULL
);
