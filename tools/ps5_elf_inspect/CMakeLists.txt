# SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.20)
project(ps5_elf_inspect CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(elf_inspect STATIC elf_inspect.cpp)
target_include_directories(elf_inspect PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ps5_elf_inspect main.cpp)
target_link_libraries(ps5_elf_inspect PRIVATE elf_inspect)

enable_testing()
add_executable(ps5_elf_inspect_test elf_inspect_test.cpp)
target_link_libraries(ps5_elf_inspect_test PRIVATE elf_inspect)
add_test(NAME ps5_elf_inspect_test COMMAND ps5_elf_inspect_test)
