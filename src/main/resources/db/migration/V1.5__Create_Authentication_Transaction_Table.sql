CREATE TABLE Authentication_transactions (
    id VARCHAR(32) PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    redirect_uri TEXT NOT NULL,
    response_type VARCHAR(20) NOT NULL,
    state TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(12),
    nonce TEXT,
    idp VARCHAR(32),
    idp_scopes JSONB,
    scopes JSONB,
    timestamp TIMESTAMP NOT NULL
);
