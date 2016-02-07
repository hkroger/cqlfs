#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "cqlfs_common.h"
#include "cassandra_ops.h"

void cassandra_log_error(CassFuture *error_future) {
    const char* message;
    size_t message_length;
    cass_future_error_message(error_future, &message, &message_length);
    debug("Error with operation: '%.*s'\n", (int)message_length, message);
}

CassFuture* cassandra_create_entry(CassSession* session, const char* path, mode_t mode) {
    CassStatement* statement = cass_statement_new("INSERT INTO entries(path, mode, created_at, modified_at, size, block_size) VALUES(?,?,?,?, 0, 65536)", 4);

    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_int64(statement, 3, time(NULL)*1000);

    CassFuture* result_future = cass_session_execute(session, statement);

    cass_statement_free(statement);

    return result_future;
}

CassFuture* cassandra_create_sub_entry(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("INSERT INTO sub_entries(sub_path, parent_path) VALUES(?,?)", 2);

    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, basename(subpathc));
    cass_statement_bind_string(statement, 1, dirname(parentpathc));

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);
    free(subpathc);
    free(parentpathc);

    return result_future;
}

void cassandra_log_keyspaces(CassSession* session) {
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
            debug("keyspace_name: '%.*s'\n", (int)keyspace_length, keyspace);
        }

        cass_result_free(result);
        cass_iterator_free(rows);
    }
}

CassFuture* cassandra_remove_entry(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(session, statement);

    cass_statement_free(statement);
    return result_future;
}

CassFuture* cassandra_remove_sub_entry(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM sub_entries WHERE parent_path = ? AND sub_path = ?", 2);
    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, dirname(parentpathc));
    cass_statement_bind_string(statement, 1, basename(subpathc));

    free(subpathc);
    free(parentpathc);

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    return result_future;
}

CassFuture* cassandra_remove_sub_entries(CassSession* session, const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM sub_entries WHERE parent_path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(session, statement);

    cass_statement_free(statement);

    return result_future;
}

CassFuture* cassandra_sub_entries(CassSession* session, const char* path, int limit) {
    CassStatement* statement = NULL;

    if (limit > 0) {
	statement = cass_statement_new("select sub_path FROM sub_entries WHERE parent_path = ? LIMIT ?", 2);
        cass_statement_bind_int32(statement, 1, limit);
    } else {
	statement = cass_statement_new("select sub_path FROM sub_entries WHERE parent_path = ?", 1);
    }
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    return result_future;
}

int cassandra_copy_full_entry(CassSession* session, const char* from, const char* to) {
    // TODO: Implement
    return -ENOSYS;
}

int cassandra_truncate(CassSession* session, const char* path, off_t size) {
    CassStatement* statement = NULL;
    
    // TODO: Delete extra blocks

    statement = cass_statement_new("UPDATE entries SET size = ? WHERE path = ?", 2);
    cass_statement_bind_int64(statement, 0, size);
    cass_statement_bind_string(statement, 1, path);
    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);
    int return_code = cass_future_error_code(result_future);

    if (return_code != CASS_OK) {
        cassandra_log_error(result_future);
        cass_future_free(result_future);
        return 1;
    }

	cass_future_free(result_future);

    return 0;
}

unsigned char* cassandra_read_block(CassSession* session, const char* path, int block, int* bytes_read) {
    CassStatement* statement = cass_statement_new("SELECT data, size FROM data_blocks WHERE path = ? AND block_number = ?", 2);
    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, block);
    unsigned char* return_data = NULL;

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);


    if (cass_future_error_code(result_future) == CASS_OK) {
		/* Retrieve result set and iterate over the rows */
		const CassResult* result = cass_future_get_result(result_future);
		CassIterator* rows = cass_iterator_from_result(result);

		if (cass_iterator_next(rows)) {
		    const CassRow* row = cass_iterator_get_row(rows);
		    const CassValue* data_value = cass_row_get_column_by_name(row, "data");
		    const CassValue* size_value = cass_row_get_column_by_name(row, "size");
	    	const cass_byte_t* cass_data;
	    	size_t size;
	    	int size2;

	    	cass_value_get_bytes(data_value, &cass_data, &size);
	    	cass_value_get_int32(size_value, &size2);
	    
			// TODO: size & size2 must match
			return_data = malloc(size);
	    	memcpy(return_data, cass_data, size);
	    	(*bytes_read) = size;
		}
	    
		cass_result_free(result);
		cass_iterator_free(rows);
    } else {
		/* Handle error */
		cassandra_log_error(result_future);
    }
    cass_future_free(result_future);

    return return_data;
}

void cassandra_write_block(CassSession* session, const char* path, int block, const unsigned char* data, int length) {
    CassStatement* statement = cass_statement_new("INSERT INTO data_blocks(path, block_number, data, size) VALUES(?,?,?,?)", 4);
    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, block);
    cass_statement_bind_bytes(statement, 2, data, length);
    cass_statement_bind_int32(statement, 3, length);

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    if (cass_future_error_code(result_future) == CASS_OK) {
		// Do nothing
    } else {
		/* Handle error */
		cassandra_log_error(result_future);
    }

    cass_future_free(result_future);
}

void cassandra_update_file_length(CassSession* session, const char* path, long size) {
    CassStatement* statement = cass_statement_new("UPDATE entries SET size = ? WHERE path = ?", 2);
    cass_statement_bind_int64(statement, 0, size);
    cass_statement_bind_string(statement, 1, path);

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    if (cass_future_error_code(result_future) == CASS_OK) {
		// Do nothing
    } else {
		/* Handle error */
		cassandra_log_error(result_future);
    }

    cass_future_free(result_future);
}


int cassandra_update_block(CassSession* session,
    const char* path,
    int block,
    int block_offset,
    const unsigned char* buf,
    int bytes_to_write,
    struct stat* stat,
    struct cfs_attrs* cfs_attrs) {

    // If no need to update existing block
    if (block * cfs_attrs->block_size >= stat->st_size) {
		cassandra_write_block(session, path, block, buf, bytes_to_write);
    } else { // update existing block
		int length = 0;
		unsigned char* data = cassandra_read_block(session, path, block, &length);
		if (length<cfs_attrs->block_size) {
	    	data = realloc(data, cfs_attrs->block_size);
		}

		memcpy(data + block_offset, buf, bytes_to_write);

		cassandra_write_block(session, path, block, data, length);

		free(data);
    }

    int newsize = block * cfs_attrs->block_size + block_offset + bytes_to_write;

    if (newsize > stat->st_size) {
		cassandra_update_file_length(session, path, newsize);
    }

    return 0;
}

int cassandra_getattr(CassSession* session, const char* path, struct stat *stbuf, struct cfs_attrs *cfs_attrs) {
    int found = 0;
    memset(stbuf, 0, sizeof(struct stat));
    memset(cfs_attrs, 0, sizeof(struct cfs_attrs));

    CassStatement* statement = cass_statement_new("SELECT mode, modified_at, size, block_size FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, path);

    CassFuture* result_future = cass_session_execute(session, statement);
    cass_statement_free(statement);

    if (cass_future_error_code(result_future) == CASS_OK) {
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
		    
		    // regular file
		    if (S_ISREG(mode)) {
				const CassValue* size_value = cass_row_get_column_by_name(row, "size");
				if (!cass_value_is_null(size_value)) {
			    	cass_int64_t size;
		    		cass_value_get_int64(size_value, &size);
					stbuf->st_size = size;
				}

				const CassValue* block_size_value = cass_row_get_column_by_name(row, "block_size");
				if (!cass_value_is_null(block_size_value)) {
			    	int size;
		    		cass_value_get_int32(block_size_value, &size);
					cfs_attrs->block_size = size;
				}
		    }
	    
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
		cassandra_log_error(result_future);
    }
    cass_future_free(result_future);
    
    if (!found) {
		return -ENOENT;
	}

    return 0;
}