add_subdirectory(cli)
add_subdirectory(commands)
add_subdirectory(crypto)

ccky_add_executable(ccky main.cpp)
target_link_libraries(ccky PRIVATE ccky_cli ccky_commands ccky_crypto)

# TODO: Maybe install by default for ccky_add_executable?
install(TARGETS ccky)
