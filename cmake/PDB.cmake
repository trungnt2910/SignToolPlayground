# CMake does not recognize PDB generator properties for clang in MinGW mode.
function(_ccky_get_target_pdb_name name pdb_name)
    set(${pdb_name} "$<TARGET_FILE_DIR:${name}>/$<TARGET_FILE_BASE_NAME:${name}>.pdb" PARENT_SCOPE)
endfunction()

function(ccky_target_pdb name)
    if(WIN32)
        _ccky_get_target_pdb_name(${name} PDB_NAME)

        # Enable PDBs for use with VS Code Debugger.
        target_compile_options(${name} PRIVATE -gcodeview)

        set_property(TARGET ${name} APPEND PROPERTY
            ADDITIONAL_CLEAN_FILES ${PDB_NAME}
        )
    endif()
endfunction()

function(ccky_target_mingw_pdb name)
    if(WIN32)
        _ccky_get_target_pdb_name(${name} PDB_NAME)

        target_link_options(${name} PRIVATE -Wl,--pdb=${PDB_NAME})

        ccky_target_pdb(${name})
    endif()
endfunction()

function(ccky_install_pdb name)
    if(WIN32)
        _ccky_get_target_pdb_name(${name} PDB_NAME)

        install(FILES ${PDB_NAME} DESTINATION Debug/${CCKY_INSTALL_ARCH})
    endif()
endfunction()

if(WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gcodeview")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -gcodeview")
endif()
