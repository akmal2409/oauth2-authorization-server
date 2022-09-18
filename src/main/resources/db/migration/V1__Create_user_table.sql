
CREATE TABLE Users (
    sub CHAR(36) PRIMARY KEY DEFAULT uuid_generate_v1() ,
    name VARCHAR(90) NOT NULL,
    username VARCHAR(40) NOT NULL,
    first_name VARCHAR(30) NOT NULL,
    middle_name VARCHAR(30),
    last_name VARCHAR(30) NOT NULL,
    zone_info VARCHAR(40),
    locale VARCHAR(10),
    updated_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    email VARCHAR(70),
    phone_number VARCHAR(20),
    email_verified BOOLEAN DEFAULT false
);
