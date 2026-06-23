include(FetchContent)

if(WIN32)
    set(CCKY_CRYPTO_BACKEND_DEPENDENCIES crypt32 wintrust ncrypt imagehlp)
else()
    set(OPENSSL_USE_STATIC_LIBS ON)
    set(ZLIB_USE_STATIC_LIBS ON)

    find_package(OpenSSL REQUIRED)
    find_package(ZLIB REQUIRED)

    FetchContent_Declare(
        pugixml
        GIT_REPOSITORY https://github.com/zeux/pugixml.git
        GIT_TAG        v1.16
        EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(pugixml)

    set(CCKY_CRYPTO_BACKEND_DEPENDENCIES OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB pugixml)
endif()

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    EXCLUDE_FROM_ALL
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
