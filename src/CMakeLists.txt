include_directories(include)

set(SOURCE_FILES pf_trace.c)
add_library(pf_trace SHARED ${SOURCE_FILES})

install(TARGETS pf_trace
        LIBRARY DESTINATION lib64)
install(DIRECTORY include/ DESTINATION /usr/include/pf_trace
        FILES_MATCHING PATTERN "*.h")

enable_testing()
add_subdirectory(test)
