cmake_minimum_required(VERSION 3.14)

project(CryptRift
        VERSION 0.1.0
        DESCRIPTION "A command-line C++ toolkit for common CTF crypto tasks"
        HOMEPAGE_URL "https://github.com/mntoyg/CryptRift"
        LANGUAGES CXX)

# Treat as top level only when configured directly, so an add_subdirectory()
# consumer does not inherit our tests.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(CRYPTRIFT_IS_TOP_LEVEL ON)
else()
  set(CRYPTRIFT_IS_TOP_LEVEL OFF)
endif()

option(CRYPTRIFT_BUILD_TESTS "Build the CryptRift test suite" ${CRYPTRIFT_IS_TOP_LEVEL})
option(CRYPTRIFT_WERROR "Treat warnings as errors" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# One place for the warning flags, applied to every target we own.
function(cryptrift_set_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4)
    if(CRYPTRIFT_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wshadow -Wpedantic)
    if(CRYPTRIFT_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

# The core library holds pure functions only: no argv, no streams, no exit.
# Everything the user sees is produced in src/cli.
add_library(cryptrift_core STATIC
  src/core/bytes.cpp
  src/core/analyze.cpp
  src/core/bignum.cpp
  src/core/classical.cpp
  src/core/codec.cpp
  src/core/rsa.cpp
  src/core/score.cpp
  src/core/xor_tool.cpp
  src/core/version.cpp)

target_include_directories(cryptrift_core PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)

cryptrift_set_warnings(cryptrift_core)

# The CLI lives in its own static library so the test binary can link it and
# drive parse_args/handlers directly, instead of only through a subprocess.
add_library(cryptrift_cli STATIC
  src/cli/args.cpp
  src/cli/binary_io.cpp
  src/cli/cmd_analyze.cpp
  src/cli/cmd_base.cpp
  src/cli/cmd_classical.cpp
  src/cli/cmd_rsa.cpp
  src/cli/cmd_xor.cpp
  src/cli/commands.cpp
  src/cli/render.cpp)

target_link_libraries(cryptrift_cli PUBLIC cryptrift_core)
target_include_directories(cryptrift_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
cryptrift_set_warnings(cryptrift_cli)

add_executable(cryptrift src/cli/main.cpp)
target_link_libraries(cryptrift PRIVATE cryptrift_cli)
cryptrift_set_warnings(cryptrift)

if(CRYPTRIFT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
