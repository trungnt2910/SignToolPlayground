ccky_add_executable(ccky_tests
    Given_CliParser.cpp
    Given_PeStore.cpp
    Given_CertMgr.cpp
    Given_SignTool.cpp
    Given_CckyHelp.cpp
    Given_CryptoFactory.cpp
)

target_link_libraries(ccky_tests PRIVATE
    ccky_commands ccky_cli ccky_crypto
    gtest_main gtest
    ${CCKY_CRYPTO_BACKEND_DEPENDENCIES}
)
include(GoogleTest)
gtest_discover_tests(ccky_tests DISCOVERY_MODE PRE_TEST WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
