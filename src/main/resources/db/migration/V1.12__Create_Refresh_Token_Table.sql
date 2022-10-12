CREATE TABLE Refresh_tokens (
    token VARCHAR(35) PRIMARY KEY,
    sub VARCHAR(36) NOT NULL,
    client_id VARCHAR(36) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    scopes jsonb NOT NULL,
    FOREIGN KEY (client_id) REFERENCES Clients(client_id),
    FOREIGN KEY (sub) REFERENCES Users(sub)
);
