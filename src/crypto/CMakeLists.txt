if(WIN32)
    ccky_add_library(ccky_crypto STATIC
        Console.cpp
        FileTypeDetector.cpp
        PvkKey.cpp
        Time.cpp
        windows/CertGenerator.cpp
        windows/Console.cpp
        windows/CryptoFactory.cpp
        windows/FileTypeDetector.cpp
        windows/KeySetDeleter.cpp
        windows/Pvk2PfxConverter.cpp
        windows/Time.cpp
        windows/Win32Cert.cpp
        windows/Win32Digest.cpp
        windows/Win32PrivateKey.cpp
        windows/Win32Signer.cpp
        windows/Win32Store.cpp
        windows/Win32Time.cpp
        windows/WinHelper.cpp
        windows/WindowsException.cpp
    )
else()
    ccky_add_library(ccky_crypto STATIC
        Console.cpp
        FileTypeDetector.cpp
        PvkKey.cpp
        Time.cpp
        openssl/AuthenticodeSigner.cpp
        openssl/CertGenerator.cpp
        openssl/Console.cpp
        openssl/CryptoFactory.cpp
        openssl/FileTypeDetector.cpp
        openssl/OpenSslCert.cpp
        openssl/OpenSslDigest.cpp
        openssl/OpenSslException.cpp
        openssl/OpenSslHelper.cpp
        openssl/OpenSslStore.cpp
        openssl/OpenSslTime.cpp
        openssl/Pvk2PfxConverter.cpp
        openssl/PvkHelper.cpp
        openssl/SpcStructures.cpp
        openssl/Time.cpp
        openssl/X509NameParser.cpp
        openssl/ZipArchive.cpp
    )
endif()

target_link_libraries(ccky_crypto PUBLIC ${CCKY_CRYPTO_BACKEND_DEPENDENCIES})
target_include_directories(ccky_crypto PUBLIC "${CMAKE_SOURCE_DIR}/include")
