CREATE TABLE tbl_role
(
    id bigint NOT NULL,
    name varchar(150),
	created_date timestamp(6) NOT NULL,
    last_modified_date timestamp(6),
    PRIMARY KEY (id),
    UNIQUE (name)
);
