function(ccky_get_host_mingw_target out_var)
    string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" _processor)

    if(_processor STREQUAL "amd64" OR _processor STREQUAL "x86_64")
        set(_target "x86_64-w64-mingw32")
    elseif(_processor STREQUAL "x86" OR _processor STREQUAL "i386" OR _processor STREQUAL "i686")
        set(_target "i686-w64-mingw32")
    elseif(_processor STREQUAL "arm64" OR _processor STREQUAL "aarch64")
        set(_target "aarch64-w64-mingw32")
    elseif(_processor MATCHES "^arm")
        set(_target "armv7-w64-mingw32")
    else()
        message(FATAL_ERROR "Unsupported host processor for CCKY_BUILD_FOR_HOST: ${CMAKE_HOST_SYSTEM_PROCESSOR}")
    endif()

    set(${out_var} "${_target}" PARENT_SCOPE)
endfunction()

function(ccky_enable_build_for_host)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "CCKY_BUILD_FOR_HOST requires clang as the C compiler.")
    endif()

    ccky_get_host_mingw_target(_ccky_target)
    message(STATUS "CCKY_BUILD_FOR_HOST enabled for ${_ccky_target}")

    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:-target;${_ccky_target}>)
    add_link_options(-target ${_ccky_target})

    set(CCKY_HOST_MINGW_TARGET "${_ccky_target}" PARENT_SCOPE)
endfunction()
