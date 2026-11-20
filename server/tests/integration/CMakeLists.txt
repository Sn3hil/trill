# SPDX-License-Identifier: MIT

add_executable(ar_integration_tests
  ipc_roundtrip_test.cpp
  control_handshake_test.cpp
)

target_link_libraries(ar_integration_tests PRIVATE ar_core GTest::gtest GTest::gtest_main)
target_include_directories(ar_integration_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../src")

include(GoogleTest)
gtest_discover_tests(ar_integration_tests
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../.."
)
