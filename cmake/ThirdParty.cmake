if(WIN32)
    set(CCKY_CRYPTO_BACKEND_DEPENDENCIES crypt32 wintrust ncrypt imagehlp)
else()
    set(OPENSSL_USE_STATIC_LIBS ON)
    find_package(OpenSSL REQUIRED)
    set(CCKY_CRYPTO_BACKEND_DEPENDENCIES OpenSSL::SSL OpenSSL::Crypto)
endif()

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
