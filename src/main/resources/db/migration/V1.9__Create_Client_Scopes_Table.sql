CREATE TABLE Client_scopes (
    client_id VARCHAR(36) NOT NULL,
    scope_id serial NOT NULL,
    FOREIGN KEY (client_id) REFERENCES Clients(client_id),
    FOREIGN KEY (scope_id) REFERENCES Scopes(id)
);
