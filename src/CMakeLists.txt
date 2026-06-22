add_subdirectory(cli)
add_subdirectory(crypto)
add_subdirectory(commands)

ccky_add_executable(ccky main.cpp)
target_link_libraries(ccky PRIVATE ccky_commands ccky_cli ccky_crypto)

# TODO: Maybe install by default for ccky_add_executable?
install(TARGETS ccky)
