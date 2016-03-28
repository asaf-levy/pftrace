include_directories(include)

set(PF_TRC_SOURCE_FILES pf_trace.c pf_writer.c)
add_library(pf_trace SHARED ${PF_TRC_SOURCE_FILES})

set(READER_SOURCE_FILES pf_reader.c)
add_executable(pf_trace_reader ${READER_SOURCE_FILES})

set(DAEMON_SOURCE_FILES pf_trace_daemon.c)
add_executable(pf_trace_daemon ${DAEMON_SOURCE_FILES})
target_link_libraries(pf_trace_daemon ${CMAKE_THREAD_LIBS_INIT} rt lf_queue pf_trace)

install(TARGETS pf_trace
        LIBRARY DESTINATION lib64)
install(TARGETS pf_trace_reader
        RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION /usr/include/pf_trace
        FILES_MATCHING PATTERN "*.h")

enable_testing()
add_subdirectory(test)
