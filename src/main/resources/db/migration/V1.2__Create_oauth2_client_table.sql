CREATE TABLE Clients (
    client_id VARCHAR(36) PRIMARY KEY,
    client_secret VARCHAR(36) NOT NULL,
    name VARCHAR(50) NOT NULL,
    require_user_consent BOOLEAN DEFAULT TRUE,
    allow_wildcards_in_redirect_urls BOOLEAN DEFAULT FALSE
);
