//
//  Cache.cpp
//  CQLFS
//
//  Created by Hannu Kröger on 22/02/16.
//
//

#include "Cache.h"

void Cache::set_user_count(int count){
    user_counter = count;
}

void Cache::inc_user_count() {
    user_counter++;
}

void Cache::dec_user_count() {
    user_counter--;
}

int Cache::user_count() {
    return user_counter;
}