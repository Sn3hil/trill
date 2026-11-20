# SPDX-License-Identifier: MIT

add_executable(fuzz_framing fuzz_framing.cpp)
target_link_libraries(fuzz_framing PRIVATE ar_core -fsanitize=fuzzer)
target_compile_options(fuzz_framing PRIVATE -fsanitize=fuzzer)

add_executable(fuzz_messages fuzz_messages.cpp)
target_link_libraries(fuzz_messages PRIVATE ar_core -fsanitize=fuzzer)
target_compile_options(fuzz_messages PRIVATE -fsanitize=fuzzer)
