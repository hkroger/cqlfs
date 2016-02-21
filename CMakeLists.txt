cmake_minimum_required (VERSION 3.4)
project (CQLFS)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -g")
file(GLOB SOURCE_FILES
            "*.h"
            "*.cpp"
)
include_directories( /usr/local/include/ )
link_directories(/usr/local/lib)
add_executable(cqlfs ${SOURCE_FILES})
target_link_libraries (cqlfs cassandra;osxfuse)

