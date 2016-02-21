use cqlfs;
insert into entries(path, mode, modified_at, created_at) VALUES('/', 16877, dateof(NOW()), dateof(NOW()));
