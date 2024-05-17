CREATE TABLE tbl_user
(
    id bigint NOT NULL,
    username varchar(255) NOT NULL,
	password varchar(255) NOT NULL,
    firstname varchar(100),
    lastname varchar(100),
	email varchar(150),
	dob date,
	gender varchar(5),
	is_account_non_expired boolean NOT NULL,
	is_account_non_locked boolean NOT NULL,
	is_credentials_non_expired boolean NOT NULL,
	is_enabled boolean NOT NULL,
    PRIMARY KEY (id),
	UNIQUE (username),
    UNIQUE (email)
);