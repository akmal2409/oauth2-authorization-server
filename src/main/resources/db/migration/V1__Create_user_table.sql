
CREATE TABLE Users (
    sub VARCHAR(36) PRIMARY KEY,
    name VARCHAR(90) NOT NULL,
    password TEXT,
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
