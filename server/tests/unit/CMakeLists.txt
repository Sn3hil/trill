# SPDX-License-Identifier: MIT

add_executable(ar_unit_tests
  encoding_test.cpp
  framing_test.cpp
  hkdf_test.cpp
  spake2_test.cpp
  device_store_test.cpp
  config_test.cpp
  messages_test.cpp
  ring_buffer_test.cpp
  paths_test.cpp
  ipc_protocol_test.cpp
  pairing_manager_test.cpp
)

target_link_libraries(ar_unit_tests PRIVATE ar_core GTest::gtest GTest::gtest_main)
target_include_directories(ar_unit_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../src")

include(GoogleTest)
gtest_discover_tests(ar_unit_tests
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../.."
)
