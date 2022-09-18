CREATE TABLE ${hibernate-types-52.version} (
    client_id CHAR(36) NOT NULL REFERENCES OAuth_2_clients(client_id),
    grant_type VARCHAR(50) NOT NULL REFERENCES OAuth_2_grants(type)
);

