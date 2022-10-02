CREATE TABLE Sessions (
    id VARCHAR(36) PRIMARY KEY,
    sub VARCHAR(36) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    remote_address TEXT NOT NULL,
    FOREIGN KEY (sub) REFERENCES Users(sub)
);
