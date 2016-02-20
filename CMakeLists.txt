cmake_minimum_required (VERSION 3.4)
project (CQLFS)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
set (SOURCE_FILES foo.cpp bar.cpp baz.cpp)
file(GLOB SOURCE_FILES
            "*.h"
            "*.cpp"
)
include_directories( ${MY_SOURCE_DIR}/src )
add_executable(cqlfs ${SOURCE_FILES})
target_link_libraries (cqlfs cassandra;osxfuse)

