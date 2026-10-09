# One test binary for the whole suite; each task appends its test_*.cpp here.
add_executable(ct_tests
  main.cpp
  cli_runner.cpp
  test_error.cpp
  test_bytes.cpp
  test_codec.cpp
  test_args.cpp
  test_cli.cpp)

target_link_libraries(ct_tests PRIVATE cryptrift_cli)
target_include_directories(ct_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR})
cryptrift_set_warnings(ct_tests)

# The CLI tests run the real binary, so it has to be built first. Its path
# reaches the test through a generated header rather than a -D define: on
# Windows that path is full of backslashes, which a plain string literal would
# read as escape sequences. A raw string literal sidesteps it.
add_dependencies(ct_tests cryptrift)
file(GENERATE
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/cryptrift_bin_path.hpp"
  CONTENT "#pragma once
#define CRYPTRIFT_BIN R\"($<TARGET_FILE:cryptrift>)\"
")

add_test(NAME unit COMMAND ct_tests)

# A harness that cannot report a failure would make every test above it
# meaningless, so one test checks exactly that: ct_selftest fails on purpose,
# and WILL_FAIL turns its non-zero exit into the passing outcome.
add_executable(ct_selftest selftest.cpp)
target_include_directories(ct_selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
cryptrift_set_warnings(ct_selftest)

add_test(NAME harness_selftest COMMAND ct_selftest)
set_tests_properties(harness_selftest PROPERTIES WILL_FAIL TRUE)
