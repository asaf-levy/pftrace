include_directories(${PROJECT_SOURCE_DIR}/src/include)

enable_testing()

set(SOURCE_FILES pf_trace_test.c)
add_executable(pf_trace_test ${SOURCE_FILES})
target_link_libraries(pf_trace_test ${CMAKE_THREAD_LIBS_INIT} rt lf_queue pf_trace)
add_test(pf_trace_test pf_trace_test)

