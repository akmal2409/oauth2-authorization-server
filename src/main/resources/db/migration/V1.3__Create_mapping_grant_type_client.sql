CREATE TABLE Client_grants (
    client_id VARCHAR(36) NOT NULL REFERENCES Clients(client_id),
    grant_type VARCHAR(50) NOT NULL REFERENCES Grants(type)
);

