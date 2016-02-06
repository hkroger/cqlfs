/* For more information, see http://www.macdevcenter.com/pub/a/mac/2007/03/06/macfuse-new-frontiers-in-file-systems.html. */ 
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <cassandra.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#define log(x...) syslog(LOG_NOTICE,x)

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION  26
#include <fuse.h>

const char  *file_path      = "/hello.txt";
const char   file_content[] = "Hello World!\n";
const size_t file_size      = sizeof(file_content)/sizeof(char) - 1;

CassCluster* cluster = NULL;
CassSession* session = NULL;
CassTimestampGen* timestamp_gen = NULL;

void log_error(CassFuture *error_future) {
    const char* message;
    size_t message_length;
    cass_future_error_message(error_future, &message, &message_length);
    log("Error with operation: '%.*s'\n", (int)message_length, message);
}



void logkeyspaces() {
    CassStatement* statement = cass_statement_new("SELECT keyspace_name FROM system.schema_keyspaces", 0);
    CassFuture* result_future = cass_session_execute(session, statement);

    if(cass_future_error_code(result_future) == CASS_OK) {
        const CassResult* result = cass_future_get_result(result_future);
        CassIterator* rows = cass_iterator_from_result(result);

        while(cass_iterator_next(rows)) {
            const CassRow* row = cass_iterator_get_row(rows);
            const CassValue* value = cass_row_get_column_by_name(row, "keyspace_name");

            const char* keyspace;
            size_t keyspace_length;
            cass_value_get_string(value, &keyspace, &keyspace_length);
            log("keyspace_name: '%.*s'\n", (int)keyspace_length, keyspace);
        }

        cass_result_free(result);
        cass_iterator_free(rows);
    }
}


int cql_access(const char* path, int mask) {
    log("access: %s, mask: %d\n", path, mask);
    return 0;
}


int cql_truncate(const char* path, off_t size) {
    log("truncate: %s, size: %lld\n", path, size);
    return -EACCES;
}

int cql_ftruncate(const char* path, off_t size, struct fuse_file_info* fi) {
    log("ftruncate: %s, size: %lld\n", path, size);
    return -EACCES;
}



int cql_write(const char* path, const char *buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    log("write: %s, size: %zu, offset: %lld\n", path, size, offset);
    return -EACCES;
}

int cql_getattr(const char *path, struct stat *stbuf) {
    log("getattr: %s\n", path);
    int found = 0;
    memset(stbuf, 0, sizeof(struct stat));

    CassStatement* statement = cass_statement_new("SELECT mode, modified_at FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, path);

    CassFuture* result_future = cass_session_execute(session, statement);

    if(cass_future_error_code(result_future) == CASS_OK) {
	/* Retrieve result set and iterate over the rows */
	const CassResult* result = cass_future_get_result(result_future);
	CassIterator* rows = cass_iterator_from_result(result);

	if (cass_iterator_next(rows)) {
	    const CassRow* row = cass_iterator_get_row(rows);
	    const CassValue* value = cass_row_get_column_by_name(row, "mode");
	    const CassValue* modified_at_value = cass_row_get_column_by_name(row, "modified_at");

	    int mode;
	    cass_value_get_int32(value, &mode);
	    stbuf->st_mode = mode;
            if (!cass_value_is_null(modified_at_value)) {
		cass_int64_t modified_at;
		cass_value_get_int64(modified_at_value, &modified_at);
	    	stbuf->st_mtime = modified_at / 1000;
            }
	    stbuf->st_nlink = 1;
	    found = 1;
	}

	cass_result_free(result);
	cass_iterator_free(rows);
    } else {
	/* Handle error */
	log_error(result_future);
    }
    cass_future_free(result_future);
    
    if (!found) {
	return -ENOENT;
    }

    return 0;
}

int cql_fgetattr(const char* path, struct stat* stbuf, struct fuse_file_info *info) {
    log("fgetattr: %s\n", path);
    return cql_getattr(path, stbuf);
}


int cql_open(const char *path, struct fuse_file_info *fi) {
    log("open: %s\n", path);

    return 0;
}

int cql_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    log("readdir: %s\n", path);
    int direxists = 0;

    CassStatement* statement_entry = cass_statement_new("select mode FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement_entry, 0, path);
    CassFuture* entry_result_future = cass_session_execute(session, statement_entry);

    CassStatement* statement = cass_statement_new("select sub_path FROM sub_entries WHERE parent_path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(session, statement);

    int res1 = cass_future_error_code(entry_result_future) == CASS_OK;
    int res2 = cass_future_error_code(result_future) == CASS_OK;

    if (res1 && res2) {
	/* Retrieve result set and iterate over the rows */
	const CassResult* result = cass_future_get_result(entry_result_future);
	CassIterator* rows = cass_iterator_from_result(result);

	if (cass_iterator_next(rows)) {
	    filler(buf, ".", NULL, 0);           /* Current directory (.)  */
	    filler(buf, "..", NULL, 0);          /* Parent directory (..)  */
	    direxists = 1;
	}

	cass_iterator_free(rows);

	if (direxists) {
	    /* Retrieve result set and iterate over the rows */
	    const CassResult* result2 = cass_future_get_result(result_future);
	    CassIterator* rows2 = cass_iterator_from_result(result2);

	    while (cass_iterator_next(rows2)) {
		const CassRow* row = cass_iterator_get_row(rows2);
		const CassValue* value = cass_row_get_column_by_name(row, "sub_path");

		const char* sub_path;
		size_t sub_path_length;
		cass_value_get_string(value, &sub_path, &sub_path_length);
		// Turn non null terminating string into null terminating string
		char *sub_path_null_terminating = calloc(1, sub_path_length + 1);
		memcpy(sub_path_null_terminating, sub_path, sub_path_length);
		filler(buf, sub_path_null_terminating, NULL, 0); 
		free(sub_path_null_terminating);
	    }

	    cass_result_free(result2);
	    cass_iterator_free(rows2);
	}
    }

    if (!res1) {
	log_error(entry_result_future);
    }

    if (!res2) {
	log_error(result_future);
    }

    cass_future_free(entry_result_future);
    cass_future_free(result_future);
    return res1 && res2 ? (direxists ? 0 : -ENOENT) : -EACCES;
}

int cql_mkdir(const char* path, mode_t mode) {
    log("mkdir: %s\n", path);

    CassStatement* statement = cass_statement_new("INSERT INTO entries(path, mode, created_at, modified_at) VALUES(?,?,?,?)", 4);

    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_int64(statement, 3, time(NULL)*1000);

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    int return_code = cass_future_error_code(result_future);
    cass_future_free(result_future);

    statement = cass_statement_new("INSERT INTO sub_entries(sub_path, mode, created_at, parent_path) VALUES(?,?,?,?)", 4);

    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, basename(subpathc));
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_string(statement, 3, dirname(parentpathc));

    result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);
    free(subpathc);
    free(parentpathc);

    return_code = return_code || cass_future_error_code(result_future);
    cass_future_free(result_future);

    if (return_code == CASS_OK) {
        return 0;
    }

    return -EACCES;
}

int cql_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    log("read: %s\n", path);
    if (strcmp(path, file_path) != 0) {
        return -ENOENT;
    }

    if (offset >= file_size) { /* Trying to read past the end of file. */
        return 0;
    }

    if (offset + size > file_size) { /* Trim the read to the file size. */
        size = file_size - offset;
    }

    memcpy(buf, file_content + offset, size); /* Provide the content. */

    return size;
}

void* cql_init(struct fuse_conn_info *conn) {
    openlog("cqlfs", 0, LOG_DAEMON);
    log("Starting CQLFS");
    /* Add contact points */
    cluster = cass_cluster_new();
    session = cass_session_new();
    timestamp_gen = cass_timestamp_gen_monotonic_new();
    cass_cluster_set_timestamp_gen(cluster, timestamp_gen);
    CassFuture* connect_future = NULL;

    cass_cluster_set_contact_points(cluster, "127.0.0.1");
    connect_future = cass_session_connect_keyspace(session, cluster, "cqlfs");

    if (cass_future_error_code(connect_future) != CASS_OK) {
        /* Handle error */
	log_error(connect_future);
        exit(1);
    }

    log("Connection to Cassandra successful");
    logkeyspaces();

    return NULL;
}

void cql_destory() {
    closelog();
}

struct fuse_operations cqlfs_filesystem_operations = {
    .fgetattr = cql_fgetattr, 
    .access  = cql_access,
    .getattr = cql_getattr,
    .open    = cql_open,
    .read    = cql_read,
    .write   = cql_write,
    .truncate = cql_truncate,
    .ftruncate = cql_ftruncate,
    .readdir = cql_readdir,
    .mkdir   = cql_mkdir,  
    .init    = cql_init,
    .destroy = cql_destory
};


int main(int argc, char **argv) {
    return fuse_main(argc, argv, &cqlfs_filesystem_operations, NULL);
}
