//
//  Cache.h
//  CQLFS
//
//  Created by Hannu Kröger on 22/02/16.
//
//

#ifndef Cache_h
#define Cache_h

#include <stdio.h>


class Cache {
public:
    void set_user_count(int count);
    void inc_user_count();
    void dec_user_count();
    int user_count();
private:
    int user_counter;
};

#endif /* FileBlockCache_hpp */

