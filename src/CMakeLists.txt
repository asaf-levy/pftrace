include_directories(include)

set(PF_TRC_SOURCE_FILES pf_trace.c pf_writer.c)
add_library(pf-trace SHARED ${PF_TRC_SOURCE_FILES})
target_link_libraries(pf-trace ${CMAKE_THREAD_LIBS_INIT} rt ${LB_LF_QUEUE})

set(READER_SOURCE_FILES pf_reader.c)
add_executable(pf-trace-reader ${READER_SOURCE_FILES})

set(DAEMON_SOURCE_FILES pf_trace_daemon.c)
add_executable(pf-trace-daemon ${DAEMON_SOURCE_FILES})
target_link_libraries(pf-trace-daemon ${CMAKE_THREAD_LIBS_INIT} pf-trace)

install(TARGETS pf-trace
        LIBRARY DESTINATION lib64)
install(TARGETS pf-trace-reader
        RUNTIME DESTINATION bin)
install(TARGETS pf-trace-daemon
        RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION /usr/include/pf-trace
        FILES_MATCHING PATTERN "*.h")

enable_testing()
add_subdirectory(test)
