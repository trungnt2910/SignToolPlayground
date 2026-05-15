ccky_add_library(ccky_cli STATIC
    CliParser.cpp
    CommandRegistry.cpp
)

target_include_directories(ccky_cli PUBLIC "${CMAKE_SOURCE_DIR}/include")
