cmake_minimum_required(VERSION 3.24)

option(CCKY_BUILD_FOR_HOST "Build with clang -target for the Windows host architecture" OFF)

project(CCKY VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
include(FetchContent)
include(cmake/CCKYBuildForHost.cmake)

if(CCKY_BUILD_FOR_HOST)
    ccky_enable_build_for_host()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

FetchContent_Declare(
    wil
    GIT_REPOSITORY https://github.com/microsoft/wil.git
    GIT_TAG v1.0.260126.7
)
set(WIL_BUILD_PACKAGING OFF CACHE BOOL "" FORCE)
set(WIL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(wil)

add_library(ccky_app STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/app/application.cpp
)
add_library(ccky::app ALIAS ccky_app)

target_include_directories(ccky_app
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(ccky_app
    PUBLIC
        WIL::WIL
)

if(WIN32)
    add_library(ccky_platform_backend STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/backend/windows_backend.cpp
    )
    target_include_directories(ccky_platform_backend
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(ccky_platform_backend
        PUBLIC
            WIL::WIL
            crypt32
            ncrypt
    )

    add_executable(ccky ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
    set_target_properties(ccky PROPERTIES OUTPUT_NAME ccky)
    target_link_libraries(ccky PRIVATE ccky::app ccky_platform_backend)
endif()

if(BUILD_TESTING)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
    )
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(ccky_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/application_tests.cpp
    )
    target_link_libraries(ccky_tests
        PRIVATE
            ccky::app
            GTest::gtest_main
    )
    target_compile_definitions(ccky_tests PRIVATE CCKY_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

    if(WIN32)
        target_sources(ccky_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_integration_tests.cpp)
        target_link_libraries(ccky_tests PRIVATE ccky_platform_backend crypt32 ncrypt)
    endif()

    include(GoogleTest)
    gtest_discover_tests(ccky_tests)
endif()

install(TARGETS ccky_app
    EXPORT CCKYTargets
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)
install(EXPORT CCKYTargets
    NAMESPACE ccky::
    DESTINATION lib/cmake/CCKY
)

if(WIN32)
    install(TARGETS ccky RUNTIME DESTINATION bin)
endif()
