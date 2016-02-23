//
//  CassandraFutureSpool.hpp
//  CQLFS
//
//  Created by Hannu Kröger on 21/02/16.
//
//

#ifndef CassandraFutureSpool_hpp
#define CassandraFutureSpool_hpp

#include <list>
#include <stdio.h>
#include <cassandra.h>
#include <mutex>

#include "Cache.h"

class CassandraFutureSpool : public Cache {
public:
    CassandraFutureSpool(int max_pending_futures);
    ~CassandraFutureSpool();
    
    void append(CassFuture* future);
    void wait_all();
    int get_errors();
    
private:
    void free_futures();
    void wait_for_pending_futures();
    void check_pending_futures();

    std::list<CassFuture*> pending_futures;
    std::list<CassFuture*> done_futures;
    std::mutex spool_mutex;
    int errors;
    int max_pending_futures;
};

#endif /* CassandraFutureSpool_hpp */
