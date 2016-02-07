#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "cqlfs_common.h"
#include "CassandraFS.h"

CassandraFS::CassandraFS(CassandraContext* ctxt) {
    this->ctxt = ctxt;
}

CassError CassandraFS::create_file(const char* path, mode_t mode) {
    CassUuid uuid;
    cass_uuid_gen_time(ctxt->uuid_gen, &uuid);
    CassError error_value = CASS_OK;

    CassFuture* result_future = NULL;

    if (S_ISDIR(mode)) {
        result_future = create_dir_entry(path, mode);
    } else {
        result_future = create_file_entry(path, &uuid, mode);
    }
    
    CassFuture* result_future2 = create_sub_entry(path);
    CassFuture* result_future3 = NULL;

    if (!S_ISDIR(mode)) {
        result_future3 = create_physical_file(&uuid);
    }

    CassError err1 = cass_future_error_code(result_future);
    CassError err2 = cass_future_error_code(result_future2);
    CassError err3 = CASS_OK; 

    if (result_future3 != NULL) {
        err3 = cass_future_error_code(result_future3);
    }

    if (err1 != CASS_OK) {
        cassandra_log_error(result_future);
        error_value = err1;
    }

    if (err2 != CASS_OK) {
        cassandra_log_error(result_future2);
        error_value = err2;
    }

    if (err3 != CASS_OK && result_future3 != NULL) {
        cassandra_log_error(result_future3);
        error_value = err3;
    }

    cass_future_free(result_future);
    cass_future_free(result_future2);
    if (result_future3 != NULL) {
        cass_future_free(result_future3);
    }

    return error_value;

}

CassFuture* CassandraFS::create_file_entry(const char* path, CassUuid* uuid, mode_t mode) {
    CassStatement* statement = cass_statement_new("INSERT INTO entries(path, mode, created_at, modified_at, physical_file_id) VALUES(?,?,?,?, ?)", 5);

    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_int64(statement, 3, time(NULL)*1000);
    cass_statement_bind_uuid(statement, 4, *uuid);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

    cass_statement_free(statement);

    return result_future;
}

CassFuture* CassandraFS::create_dir_entry(const char* path, mode_t mode) {
    CassStatement* statement = cass_statement_new("INSERT INTO entries(path, mode, created_at, modified_at) VALUES(?,?,?,?)", 4);

    cass_statement_bind_string(statement, 0, path);
    cass_statement_bind_int32(statement, 1, mode);
    cass_statement_bind_int64(statement, 2, time(NULL)*1000);
    cass_statement_bind_int64(statement, 3, time(NULL)*1000);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

    cass_statement_free(statement);

    return result_future;
}

CassFuture* CassandraFS::create_physical_file(CassUuid* uuid) {
    CassStatement* statement = cass_statement_new("INSERT INTO physical_files(id, size, block_size) VALUES(?, 0, 65536)", 1);
    cass_statement_bind_uuid(statement, 0, *uuid);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

    cass_statement_free(statement);

    return result_future;

}

CassFuture* CassandraFS::create_sub_entry(const char* path) {
    CassStatement* statement = cass_statement_new("INSERT INTO sub_entries(sub_path, parent_path) VALUES(?,?)", 2);

    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, basename(subpathc));
    cass_statement_bind_string(statement, 1, dirname(parentpathc));

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    free(subpathc);
    free(parentpathc);

    return result_future;
}

CassFuture* CassandraFS::remove_entry(const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

    cass_statement_free(statement);
    return result_future;
}

CassFuture* CassandraFS::remove_sub_entry(const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM sub_entries WHERE parent_path = ? AND sub_path = ?", 2);
    char *subpathc = strdup(path);
    char *parentpathc = strdup(path);

    cass_statement_bind_string(statement, 0, dirname(parentpathc));
    cass_statement_bind_string(statement, 1, basename(subpathc));

    free(subpathc);
    free(parentpathc);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);

    return result_future;
}

CassFuture* CassandraFS::remove_sub_entries(const char* path) {
    CassStatement* statement = cass_statement_new("DELETE FROM sub_entries WHERE parent_path = ?", 1);
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

    cass_statement_free(statement);

    return result_future;
}

CassFuture* CassandraFS::sub_entries(const char* path, int limit) {
    CassStatement* statement = NULL;

    if (limit > 0) {
        statement = cass_statement_new("select sub_path FROM sub_entries WHERE parent_path = ? LIMIT ?", 2);
        cass_statement_bind_int32(statement, 1, limit);
    } else {
        statement = cass_statement_new("select sub_path FROM sub_entries WHERE parent_path = ?", 1);
    }
    cass_statement_bind_string(statement, 0, path);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);

    return result_future;
}

int CassandraFS::update_timestamps(const char* path, const struct timespec last_access_stamp, const struct timespec last_modification_stamp) {
    CassStatement* statement = cass_statement_new("UPDATE entries SET modified_at = ? WHERE path = ?", 2);
    cass_statement_bind_int64(statement, 0, last_modification_stamp.tv_sec * 1000 + (last_modification_stamp.tv_nsec / 1000000));
    cass_statement_bind_string(statement, 1, path);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    int error = 0;

    if (cass_future_error_code(result_future) == CASS_OK) {
        // Nada
    } else {
        /* Handle error */
        error = -EIO;
        cassandra_log_error(result_future);
    }
    cass_future_free(result_future);
        
    return error;
}

int CassandraFS::update_mode(const char* path, mode_t new_mode) {
    CassStatement* statement = cass_statement_new("UPDATE entries SET mode = ? WHERE path = ?", 2);
    cass_statement_bind_int32(statement, 0, new_mode);
    cass_statement_bind_string(statement, 1, path);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    int error = 0;

    if (cass_future_error_code(result_future) == CASS_OK) {
        // Nada
    } else {
        /* Handle error */
        error = -EIO;
        cassandra_log_error(result_future);
    }
    cass_future_free(result_future);
        
    return error;
}

int CassandraFS::hardlink(const char* from, const char* to) {
    int operation_done = 0;
    CassStatement* statement = cass_statement_new("SELECT mode, created_at, modified_at, physical_file_id FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, from);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    int error = 0;

    if (cass_future_error_code(result_future) == CASS_OK) {
		/* Retrieve result set and iterate over the rows */
		const CassResult* result = cass_future_get_result(result_future);
		CassIterator* rows = cass_iterator_from_result(result);

		if (cass_iterator_next(rows)) {
		    const CassRow* row = cass_iterator_get_row(rows);
		    const CassValue* mode_value = cass_row_get_column_by_name(row, "mode");
		    const CassValue* modified_at_value = cass_row_get_column_by_name(row, "modified_at");
		    const CassValue* created_at_value = cass_row_get_column_by_name(row, "created_at");
		    const CassValue* physical_file_id_value = cass_row_get_column_by_name(row, "physical_file_id");

		    int mode;
		    cass_value_get_int32(mode_value, &mode);

		    cass_int64_t modified_at;
		    cass_value_get_int64(modified_at_value, &modified_at);

		    cass_int64_t created_at;
		    cass_value_get_int64(created_at_value, &created_at);

            CassUuid physical_file_id;
		    cass_value_get_uuid(physical_file_id_value, &physical_file_id);

            CassStatement* insert_statement = cass_statement_new("INSERT INTO entries(path, mode, created_at, modified_at, physical_file_id) VALUES(?,?,?,?,?)", 5);
            cass_statement_bind_string(insert_statement, 0, to);
            cass_statement_bind_int32(insert_statement, 1, mode);
            cass_statement_bind_int64(insert_statement, 2, created_at);
            cass_statement_bind_int64(insert_statement, 3, modified_at);
            cass_statement_bind_uuid(insert_statement, 4, physical_file_id);
            
            CassFuture* insert_future2 = create_sub_entry(to);

            CassFuture* insert_future = cass_session_execute(ctxt->session, insert_statement);
            cass_statement_free(insert_statement);
            if (cass_future_error_code(insert_future) == CASS_OK) {
                operation_done = 1;
            } else {
                operation_done = 0;
                cassandra_log_error(insert_future);
            }

            if (cass_future_error_code(insert_future2) == CASS_OK) {
                operation_done = 1;
            } else {
                operation_done = 0;
                cassandra_log_error(insert_future2);
            }

            cass_future_free(insert_future);
            cass_future_free(insert_future2);

		}
	    
		cass_result_free(result);
		cass_iterator_free(rows);
    } else {
		/* Handle error */
        error = -EIO;
		cassandra_log_error(result_future);
    }
    cass_future_free(result_future);
    
    if (!operation_done) {
		return -ENOENT;
	}

    return error;
}

int CassandraFS::truncate(const char* path, off_t size) {
    CassStatement* statement = NULL;
    struct stat stat;
    struct cfs_attrs cfs_attrs;
    
    // TODO: Delete extra blocks
    int err = getattr(path, &stat, &cfs_attrs);

    if (err != 0) {
        return -EIO;
    }

    statement = cass_statement_new("UPDATE physical_files SET size = ? WHERE id = ?", 2);
    cass_statement_bind_int64(statement, 0, size);
    cass_statement_bind_uuid(statement, 1, cfs_attrs.physical_file_id);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    CassError return_code = cass_future_error_code(result_future);

    if (return_code != CASS_OK) {
        cassandra_log_error(result_future);
        cass_future_free(result_future);
        return -EIO;
    }

	cass_future_free(result_future);

    return 0;
}

unsigned char* CassandraFS::read_block(CassUuid* physical_file_id, int block, int* bytes_read) {
    CassStatement* statement = cass_statement_new("SELECT data, size FROM file_blocks WHERE physical_file_id = ? AND block_number = ?", 2);
    cass_statement_bind_uuid(statement, 0, *physical_file_id);
    cass_statement_bind_int32(statement, 1, block);
    unsigned char* return_data = NULL;

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
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
			return_data = (unsigned char*)malloc(size);
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

void CassandraFS::write_block(CassUuid* physical_file_id, int block, const unsigned char* data, int length) {
    CassStatement* statement = cass_statement_new("INSERT INTO file_blocks(physical_file_id, block_number, data, size) VALUES(?,?,?,?)", 4);
    cass_statement_bind_uuid(statement, 0, *physical_file_id);
    cass_statement_bind_int32(statement, 1, block);
    cass_statement_bind_bytes(statement, 2, data, length);
    cass_statement_bind_int32(statement, 3, length);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);

    if (cass_future_error_code(result_future) == CASS_OK) {
		// Do nothing
    } else {
		/* Handle error */
		cassandra_log_error(result_future);
    }

    cass_future_free(result_future);
}

void CassandraFS::update_file_length(CassUuid* physical_file_id, long size) {
    CassStatement* statement = cass_statement_new("UPDATE physical_files SET size = ? WHERE id = ?", 2);
    cass_statement_bind_int64(statement, 0, size);
    cass_statement_bind_uuid(statement, 1, *physical_file_id);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);

    if (cass_future_error_code(result_future) == CASS_OK) {
		// Do nothing
    } else {
		/* Handle error */
		cassandra_log_error(result_future);
    }

    cass_future_free(result_future);
}


int CassandraFS::update_block(CassUuid* physical_file_id,
    int block,
    int block_offset,
    const unsigned char* buf,
    int bytes_to_write,
    struct stat* stat,
    struct cfs_attrs* cfs_attrs) {

    debug("Updating block %d (offset: %d) with %d bytes", block, block_offset, bytes_to_write);

    // If no need to update existing block
    if (block * cfs_attrs->block_size >= stat->st_size) {
		write_block(physical_file_id, block, buf, bytes_to_write);
    } else { // update existing block
		int length = 0;
		unsigned char* data = read_block(physical_file_id, block, &length);
		if (length<cfs_attrs->block_size) {
	    	data = (unsigned char*)realloc(data, cfs_attrs->block_size);
		}

		memcpy(data + block_offset, buf, bytes_to_write);

		write_block(physical_file_id, block, data, block_offset + bytes_to_write);

		free(data);
    }

    int newsize = block * cfs_attrs->block_size + block_offset + bytes_to_write;

    if (newsize > stat->st_size) {
		update_file_length(physical_file_id, newsize);
    }

    return 0;
}

CassError CassandraFS::read_physical_file_info(struct stat* stat, struct cfs_attrs* cfs_attrs) {
    CassStatement* statement = cass_statement_new("SELECT size, block_size FROM physical_files WHERE id = ?", 1);
    cass_statement_bind_uuid(statement, 0, cfs_attrs->physical_file_id);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    CassError error = cass_future_error_code(result_future);

    if (error == CASS_OK) {
		/* Retrieve result set and iterate over the rows */
		const CassResult* result = cass_future_get_result(result_future);
		CassIterator* rows = cass_iterator_from_result(result);

		if (cass_iterator_next(rows)) {
		    const CassRow* row = cass_iterator_get_row(rows);

            const CassValue* size_value = cass_row_get_column_by_name(row, "size");
            if (!cass_value_is_null(size_value)) {
                cass_int64_t size;
                cass_value_get_int64(size_value, &size);
                stat->st_size = size;
            }

            const CassValue* block_size_value = cass_row_get_column_by_name(row, "block_size");
            if (!cass_value_is_null(block_size_value)) {
                int size;
                cass_value_get_int32(block_size_value, &size);
                cfs_attrs->block_size = size;
            }
		}
	    
		cass_result_free(result);
		cass_iterator_free(rows);
    } else {
		/* Handle error */
		cassandra_log_error(result_future);
    }
    cass_future_free(result_future);

    return error;
}

int CassandraFS::getattr(const char* path, struct stat *stbuf, struct cfs_attrs *cfs_attrs) {
    int found = 0;
    memset(stbuf, 0, sizeof(struct stat));
    memset(cfs_attrs, 0, sizeof(struct cfs_attrs));

    CassStatement* statement = cass_statement_new("SELECT mode, modified_at, physical_file_id FROM entries WHERE path = ?", 1);
    cass_statement_bind_string(statement, 0, path);

    CassFuture* result_future = cass_session_execute(ctxt->session, statement);
    cass_statement_free(statement);
    int error = 0;

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
                const CassValue* file_id_value = cass_row_get_column_by_name(row, "physical_file_id");
				if (!cass_value_is_null(file_id_value)) {
		    		cass_value_get_uuid(file_id_value, &(cfs_attrs->physical_file_id));
				}

                CassError phys_err = read_physical_file_info(stbuf, cfs_attrs);

                if (phys_err != CASS_OK) {
                    error = -EIO;
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
        error = -EIO;
		cassandra_log_error(result_future);
    }
    cass_future_free(result_future);
    
    if (!found) {
		return -ENOENT;
	}

    return error;
}

CassFuture* CassandraFS::remove_physical_file(struct stat* stat, struct cfs_attrs* cfs_attrs) {
    // TODO: Free blocks
    CassStatement* statement = cass_statement_new("DELETE FROM physical_files WHERE id = ?", 1);
    cass_statement_bind_uuid(statement, 0, cfs_attrs->physical_file_id);
    CassFuture* result_future = cass_session_execute(ctxt->session, statement);

    cass_statement_free(statement);

    return result_future;
}

int CassandraFS::unlink(const char* path) {
    struct stat stat;
    struct cfs_attrs cfs_attrs;
    int attr_err = getattr(path, &stat, &cfs_attrs);

    if (attr_err) {
        return attr_err;
    }

    CassFuture* result_future = remove_entry(path);
    CassFuture* result_future2 = remove_sub_entry(path);
    CassFuture* result_future3 = remove_sub_entries(path);
    CassFuture* result_future4 = NULL;
    
    if (!S_ISDIR(stat.st_mode)) {
        result_future4 = remove_physical_file(&stat, &cfs_attrs);
    }

    int error = 0;

    if (cass_future_error_code(result_future) != CASS_OK) {
        cassandra_log_error(result_future);
        error = 1;
    } 

    if (cass_future_error_code(result_future2) != CASS_OK) {
        cassandra_log_error(result_future2);
        error = 1;
    } 

    if (cass_future_error_code(result_future3) != CASS_OK) {
        cassandra_log_error(result_future3);
        error = 1;
    } 

    if (result_future4 != NULL && cass_future_error_code(result_future4) != CASS_OK) {
        cassandra_log_error(result_future4);
        error = 1;
    } 

    cass_future_free(result_future);
    cass_future_free(result_future2);
    cass_future_free(result_future3);

    if (result_future4) {
        cass_future_free(result_future4);
    }
    
    if (error) {
        return -EIO;
    }
    
    return 0;
}