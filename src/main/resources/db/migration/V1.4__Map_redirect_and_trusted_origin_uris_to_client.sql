CREATE TABLE Client_sign_in_redirect_uris (
    client_id VARCHAR(36) NOT NULL REFERENCES Clients(client_id),
    uri TEXT NOT NULL
);

CREATE TABLE Client_sign_out_redirect_uris (
 client_id VARCHAR(36) NOT NULL REFERENCES Clients(client_id),
 uri TEXT NOT NULL
);

CREATE TABLE Client_trusted_origins_uris (
  client_id VARCHAR(36) NOT NULL REFERENCES Clients(client_id),
  uri TEXT NOT NULL
);
