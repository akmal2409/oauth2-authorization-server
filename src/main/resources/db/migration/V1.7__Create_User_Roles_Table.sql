CREATE TABLE User_roles (
    user_id VARCHAR(32),
    role_id serial,
    FOREIGN KEY (user_id) REFERENCES Users(sub),
    FOREIGN KEY (role_id) REFERENCES Roles(id)
);
