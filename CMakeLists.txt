cmake_minimum_required(VERSION 3.24)
project(ccky CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(cmake/ThirdParty.cmake)

include(cmake/Architecture.cmake)
include(cmake/PDB.cmake)
include(cmake/Sanitizers.cmake)
include(cmake/Targets.cmake)

add_subdirectory(src)
enable_testing()
add_subdirectory(tests)
