# One test binary for the whole suite; each task appends its test_*.cpp here.
add_executable(ct_tests
  main.cpp
  test_error.cpp)

target_link_libraries(ct_tests PRIVATE cryptrift_core)
target_include_directories(ct_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
cryptrift_set_warnings(ct_tests)

add_test(NAME unit COMMAND ct_tests)

# A harness that cannot report a failure would make every test above it
# meaningless, so one test checks exactly that: ct_selftest fails on purpose,
# and WILL_FAIL turns its non-zero exit into the passing outcome.
add_executable(ct_selftest selftest.cpp)
target_include_directories(ct_selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
cryptrift_set_warnings(ct_selftest)

add_test(NAME harness_selftest COMMAND ct_selftest)
set_tests_properties(harness_selftest PROPERTIES WILL_FAIL TRUE)
