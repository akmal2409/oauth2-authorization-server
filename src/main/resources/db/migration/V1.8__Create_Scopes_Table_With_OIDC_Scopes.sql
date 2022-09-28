CREATE TABLE Scopes (
    id serial PRIMARY KEY,
    name VARCHAR(60) NOT NULL,
    is_oidc_scope BOOLEAN NOT NULL DEFAULT FALSE,
    description VARCHAR(90) NOT NULL
);

INSERT INTO Scopes VALUES
(1, 'openid', 'Allow application to verify your identity'),
(2, 'profile', 'Allow application to access to basic information such as name, username, picture etc'),
(3, 'email', 'Allow application to see your email address');
