include_directories(${PROJECT_SOURCE_DIR}/src/include)

enable_testing()

set(SOURCE_FILES pf_trace_test.c)
add_executable(pf-trace-test ${SOURCE_FILES})
target_link_libraries(pf-trace-test ${CMAKE_THREAD_LIBS_INIT} pf-trace)
add_test(pf-trace-test pf-trace-test)

