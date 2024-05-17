CREATE TABLE tbl_user_roles (
  users_id bigint NOT NULL,
  roles_id bigint NOT NULL,
  PRIMARY KEY (users_id,roles_id),
  CONSTRAINT fk_tbl_role FOREIGN KEY (roles_id) REFERENCES tbl_role(id),
  CONSTRAINT fk_tbl_user FOREIGN KEY (users_id) REFERENCES tbl_user(id)
);