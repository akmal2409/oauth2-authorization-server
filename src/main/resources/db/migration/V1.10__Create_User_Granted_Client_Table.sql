CREATE TABLE User_granted_clients (
    sub VARCHAR(36) NOT NULL,
    client_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (sub, client_id)
);

CREATE TABLE User_granted_client_scopes(
    sub VARCHAR(36) NOT NULL,
    client_id VARCHAR(36) NOT NULL,
    scope_id serial NOT NULL,
    FOREIGN KEY (sub, client_id) REFERENCES User_granted_clients(sub, client_id),
    FOREIGN KEY (scope_id) REFERENCES Scopes(id)
);
