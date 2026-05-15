set(CCKY_ASAN_ARCH ${CCKY_ARCH})
# For some weird reasons, i686 MinGW provides libclang_rt.asan_dynamic-i386.dll.
# Note the i386, not i686.
if(CCKY_ASAN_ARCH MATCHES "i686")
    set(CCKY_ASAN_ARCH "i386")
endif()

set(CCKY_ASAN_ARCH_SUPPORTED TRUE)

# Disable ASAN for ARM-based targets since our LLVM builds
# do not provide the required runtime libraries.
if(CCKY_ASAN_ARCH MATCHES "armv7|aarch64")
    set(CCKY_ASAN_ARCH_SUPPORTED FALSE)
endif()

# Enabling sanitizers forces the executable to be dynamically linked to these.
set(CCKY_SANITIZER_DLLS
    "libc++.dll"
    "libclang_rt.asan_dynamic-${CCKY_ASAN_ARCH}.dll"
    "libunwind.dll"
)

function(ccky_target_add_sanitizers name)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(CCKY_ASAN_ARCH_SUPPORTED)
            target_compile_options(${name} PRIVATE -fsanitize=address)
            target_link_options(${name} PRIVATE -fsanitize=address)
        endif()

        target_compile_options(${name} PRIVATE -fsanitize=undefined)
        target_link_options(${name} PRIVATE -fsanitize=undefined)
    endif()
endfunction()

function(ccky_install_sanitizers name)
    # For MinGW targets, copy the DLLs to the same directory as the executable to avoid weird
    # missing DLL errors.
    # UNIX targets should already have them in the library path.
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CCKY_ASAN_ARCH_SUPPORTED AND MINGW)
        foreach(DLL_NAME ${CCKY_SANITIZER_DLLS})
            # Ask clang where the libraries are.
            # It expects a path relative to the toolchain root.
            # We must use the ${ARCH}-w64-mingw32 folder;
            # the top-level bin/ is specific to the host architecture.
            # The actual .dlls are in bin/; lib/ contains the glue libraries.
            execute_process(
                COMMAND ${CMAKE_CXX_COMPILER}
                        --print-file-name=${CCKY_ARCH}-w64-mingw32/bin/${DLL_NAME}
                OUTPUT_VARIABLE DLL_PATH_${DLL_NAME}
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
            )

            if(DLL_PATH_${DLL_NAME})
                add_custom_command(TARGET ${name} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${DLL_PATH_${DLL_NAME}}"
                        "$<TARGET_FILE_DIR:${name}>/${DLL_NAME}"
                )

                set_property(TARGET ${name} APPEND PROPERTY
                    ADDITIONAL_CLEAN_FILES "$<TARGET_FILE_DIR:${name}>/${DLL_NAME}"
                )

                install(FILES "${DLL_PATH_${DLL_NAME}}" DESTINATION bin/${CCKY_INSTALL_ARCH})
            endif()
        endforeach()
    endif()
endfunction()
