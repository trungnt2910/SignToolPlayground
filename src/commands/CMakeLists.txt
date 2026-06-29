ccky_add_library(ccky_commands STATIC
    CertMgrCommand.cpp
    MakeCertCommand.cpp
    Pvk2PfxCommand.cpp
    SignToolCommand.cpp
)

target_include_directories(ccky_commands PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(ccky_commands PUBLIC ccky_cli ccky_crypto)
