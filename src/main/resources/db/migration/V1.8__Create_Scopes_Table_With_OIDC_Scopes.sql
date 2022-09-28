CREATE TABLE Scopes (
    id serial PRIMARY KEY,
    name VARCHAR(60) NOT NULL,
    is_oidc_scope BOOLEAN NOT NULL DEFAULT FALSE,
    description VARCHAR(90) NOT NULL
);

CREATE INDEX scope_name_idx ON Scopes(name);

INSERT INTO Scopes VALUES
(1, 'openid', true, 'Allow application to verify your identity'),
(2, 'profile', true, 'Allow application to access to basic information such as name, username, picture etc'),
(3, 'address', true, 'Allow application to view your address'),
(4, 'phone', true, 'Allow application to view your phone'),
(5, 'offline_access', true, 'Allow application to renew access to your account automatically'),
(3, 'email', true, 'Allow application to see your email address');
