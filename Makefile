cqlfs: cqlfs.c
	gcc cqlfs.c  -lcassandra -losxfuse -I/usr/local/include/osxfuse/fuse -o cqlfs -Werror

cassandratest: cassandratest.c
	gcc cassandratest.c  -lcassandra -o cassandratest 
