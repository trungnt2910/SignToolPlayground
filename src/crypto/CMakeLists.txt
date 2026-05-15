if(WIN32)
    ccky_add_library(ccky_crypto STATIC
        TimeFormatter.cpp
        windows/CryptoFactory.cpp
        windows/WinCert.cpp
        windows/WinStore.cpp
        windows/WinSigner.cpp
        windows/WindowsException.cpp
        windows/WinHelper.cpp
    )
else()
    ccky_add_library(ccky_crypto STATIC
        TimeFormatter.cpp
        openssl/AuthenticodeSigner.cpp
        openssl/CryptoFactory.cpp
        openssl/OpenSslCert.cpp
        openssl/OpenSslStore.cpp
        openssl/OpenSslWrapper.cpp
        openssl/OpenSslException.cpp
    )
endif()

target_link_libraries(ccky_crypto PUBLIC ${CCKY_CRYPTO_BACKEND_DEPENDENCIES})
target_include_directories(ccky_crypto PUBLIC "${CMAKE_SOURCE_DIR}/include")
