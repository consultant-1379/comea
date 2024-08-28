set( COMEA_DIR ${CMAKE_CURRENT_LIST_DIR} )

# Adding subdirectories based on host OS
if (${HOST_OS} MATCHES "el.*")
  add_subdirectory( rhel6 )
else ()
  add_subdirectory( sles12 )
endif ()

