#include "CassandraFutureSpool.h"
#include "cqlfs_common.h"

// In microseconds
#define SLEEP_BETWEEN_CHECKS 1000

CassandraFutureSpool::CassandraFutureSpool(int max_pending_futures) {
    errors = 0;
    this->max_pending_futures = max_pending_futures;
}

CassandraFutureSpool::~CassandraFutureSpool() {
    wait_all();
    free_futures();
}

void CassandraFutureSpool::append(CassFuture* future) {
    std::lock_guard<std::mutex> lock(spool_mutex);

    wait_for_pending_futures();
    pending_futures.push_back(future);
}

void CassandraFutureSpool::wait_for_pending_futures() {
    while (pending_futures.size() > max_pending_futures) {
        check_pending_futures();
        
        if (pending_futures.size() > max_pending_futures) {
            usleep(SLEEP_BETWEEN_CHECKS);
        }
    }
}

int CassandraFutureSpool::get_errors() {
    return errors;
}


void CassandraFutureSpool::free_futures() {
    std::lock_guard<std::mutex> lock(spool_mutex);

    for (std::list<CassFuture*>::iterator it=pending_futures.begin(); it != pending_futures.end(); ++it) {
        cass_future_free(*it);
    }
    pending_futures.clear();
    for (std::list<CassFuture*>::iterator it=done_futures.begin(); it != done_futures.end(); ++it) {
        cass_future_free(*it);
    }
    done_futures.clear();
}

void CassandraFutureSpool::check_pending_futures() {
    for (std::list<CassFuture*>::iterator it=pending_futures.begin(); it != pending_futures.end();) {
        if (cass_future_ready(*it)) {
            if (cass_future_error_code(*it) != CASS_OK) {
                cassandra_log_error(*it);
                errors++;
            }
            
            done_futures.push_back(*it);
            it = pending_futures.erase(it);
        } else {
            ++it;
        }
    }
}

void CassandraFutureSpool::wait_all() {
    std::lock_guard<std::mutex> lock(spool_mutex);

    for (std::list<CassFuture*>::iterator it=pending_futures.begin(); it != pending_futures.end();) {
        if (cass_future_error_code(*it) != CASS_OK) {
            cassandra_log_error(*it);
            errors++;
        }
        done_futures.push_back(*it);
        it = pending_futures.erase(it);
    }
}