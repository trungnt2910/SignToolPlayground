# Custom CMake target wrappers for ccky

function(ccky_add_executable target)
    add_executable(${target} ${ARGN})
    target_link_options(${target} PRIVATE -static)
    ccky_target_mingw_pdb(${target})
    ccky_target_add_sanitizers(${target})
    ccky_install_sanitizers(${target})
endfunction()

function(ccky_add_library target type)
    add_library(${target} ${type} ${ARGN})
    ccky_target_pdb(${target})
    ccky_target_add_sanitizers(${target})
endfunction()
