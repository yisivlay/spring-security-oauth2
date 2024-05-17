ALTER TABLE tbl_user
ADD COLUMN createdby_id bigint,
ADD COLUMN created_date timestamp(6) NOT NULL,
ADD COLUMN lastmodifiedby_id bigint,
ADD COLUMN lastmodified_date timestamp(6) NOT NULL;