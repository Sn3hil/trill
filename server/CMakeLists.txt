# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.25)
project(trill VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TRILL_BUILD_TESTS "Build unit and integration tests" ON)
option(TRILL_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(TRILL_ENABLE_DEV_PAIRING "Compile the insecure dev pairing path" OFF)
option(TRILL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(TRILL_SANITIZERS "" CACHE STRING "Comma separated: address,undefined,thread")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(OpenSSL 3 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ROC IMPORTED_TARGET roc)
if(ROC_FOUND)
  # Some split-output distributions install roc.pc in the -dev output while
  # prefix= still points at the runtime output (so includedir does not exist).
  # Keep only directories that exist and fall back to the include directory
  # next to pcfiledir, which is correct for those layouts.
  set(_roc_includes "")
  foreach(_dir IN LISTS ROC_INCLUDE_DIRS)
    if(EXISTS "${_dir}")
      list(APPEND _roc_includes "${_dir}")
    endif()
  endforeach()
  if(NOT _roc_includes)
    pkg_get_variable(ROC_PC_DIR roc pcfiledir)
    get_filename_component(_roc_candidate "${ROC_PC_DIR}/../../include" ABSOLUTE)
    if(EXISTS "${_roc_candidate}/roc/context.h")
      list(APPEND _roc_includes "${_roc_candidate}")
    endif()
  endif()
  if(_roc_includes)
    set_target_properties(PkgConfig::ROC PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${_roc_includes}")
  endif()
endif()
if(NOT ROC_FOUND)
  find_package(Roc REQUIRED)
  set(ROC_TARGET Roc::Roc)
else()
  set(ROC_TARGET PkgConfig::ROC)
endif()
pkg_check_modules(PIPEWIRE REQUIRED IMPORTED_TARGET libpipewire-0.3)
pkg_check_modules(AVAHI REQUIRED IMPORTED_TARGET avahi-client)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)

find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)
find_path(SPDLOG_INCLUDE_DIR spdlog/spdlog.h)

if(TRILL_BUILD_TESTS)
  find_package(GTest CONFIG REQUIRED)
endif()

# ---------------------------------------------------------------------------
# Warnings / sanitizers
# ---------------------------------------------------------------------------
add_library(ar_flags INTERFACE)
target_compile_options(ar_flags INTERFACE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor
  -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual
  $<$<CXX_COMPILER_ID:Clang>:-Wnull-dereference>
  $<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
target_compile_definitions(ar_flags INTERFACE
  ASIO_STANDALONE ASIO_NO_DEPRECATED SPDLOG_FMT_EXTERNAL=1)
if(TRILL_WARNINGS_AS_ERRORS)
  target_compile_options(ar_flags INTERFACE -Werror)
endif()
if(TRILL_ENABLE_DEV_PAIRING)
  target_compile_definitions(ar_flags INTERFACE TRILL_ENABLE_DEV_PAIRING=1)
endif()

if(TRILL_SANITIZERS)
  string(REPLACE "," ";" _san "${TRILL_SANITIZERS}")
  string(REPLACE ";" "," _san_flags "${_san}")
  add_compile_options(-fsanitize=${_san_flags} -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${_san_flags})
endif()

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
add_library(ar_core STATIC
  src/common/error.cpp
  src/common/log.cpp
  src/common/paths.cpp
  src/common/encoding.cpp
  src/store/config.cpp
  src/store/device_store.cpp
  src/store/identity.cpp
  src/crypto/spki.cpp
  src/crypto/hkdf.cpp
  src/crypto/spake2.cpp
  src/crypto/csprng.cpp
  src/net/framing.cpp
  src/net/tls.cpp
  src/net/control_server.cpp
  src/net/mdns.cpp
  src/protocol/messages.cpp
  src/pairing/pairing_manager.cpp
  src/session/control_session.cpp
  src/session/session_manager.cpp
  src/audio/pw_sink.cpp
  src/audio/pw_source.cpp
  src/audio/default_sink_guard.cpp
  src/audio/roc_sender.cpp
  src/audio/roc_receiver.cpp
  src/audio/stream_pipeline.cpp
  src/audio/mic_pipeline.cpp
  src/cli/ipc_client.cpp
  src/ipc/ipc_server.cpp
  src/ipc/ipc_protocol.cpp
  src/ipc/commands.cpp
  src/daemon/pairing_session.cpp
  src/daemon/daemon.cpp)
target_include_directories(ar_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories(ar_core SYSTEM PUBLIC
  "${ASIO_INCLUDE_DIR}")
target_link_libraries(ar_core PUBLIC
  ar_flags
  OpenSSL::SSL OpenSSL::Crypto Threads::Threads
  ${ROC_TARGET} PkgConfig::PIPEWIRE PkgConfig::AVAHI
  nlohmann_json::nlohmann_json spdlog::spdlog CLI11::CLI11 tomlplusplus::tomlplusplus)
target_compile_definitions(ar_core PUBLIC
  TRILL_VERSION="${PROJECT_VERSION}"
  $<$<BOOL:${TRILL_ENABLE_DEV_PAIRING}>:TRILL_ENABLE_DEV_PAIRING=1>)

# ---------------------------------------------------------------------------
# Binaries
# ---------------------------------------------------------------------------
add_executable(trilld src/daemon/main_daemon.cpp)
target_link_libraries(trilld PRIVATE ar_core)

add_executable(trill src/cli/main_cli.cpp src/cli/render.cpp)
target_link_libraries(trill PRIVATE ar_core)

add_executable(trill-testclient
  src/testclient/main_testclient.cpp)
target_link_libraries(trill-testclient PRIVATE ar_core)

install(TARGETS trilld trill RUNTIME DESTINATION bin)
install(FILES packaging/systemd/trilld.service
        DESTINATION lib/systemd/user)
install(FILES packaging/man/trill.1 DESTINATION share/man/man1)
install(DIRECTORY packaging/completions/
        DESTINATION share/bash-completion/completions
        FILES_MATCHING PATTERN "trill.bash")
install(DIRECTORY packaging/completions/
        DESTINATION share/zsh/site-functions
        FILES_MATCHING PATTERN "trill.zsh")
install(DIRECTORY packaging/completions/
        DESTINATION share/fish/vendor_completions.d
        FILES_MATCHING PATTERN "trill.fish")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(TRILL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests/unit)
  add_subdirectory(tests/integration)
  if(TRILL_BUILD_FUZZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_subdirectory(tests/fuzz)
  endif()
endif()
