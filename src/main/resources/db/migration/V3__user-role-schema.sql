CREATE TABLE tbl_user_role (
  user_id bigint NOT NULL,
  role_id bigint NOT NULL,
  PRIMARY KEY (user_id,role_id),
  CONSTRAINT fk_tbl_role FOREIGN KEY (role_id) REFERENCES tbl_role(id),
  CONSTRAINT fk_tbl_user FOREIGN KEY (user_id) REFERENCES tbl_user(id)
);