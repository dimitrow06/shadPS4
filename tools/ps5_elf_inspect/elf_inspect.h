// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ElfInspect {

enum class Container {
    Unknown,
    Elf,
    Self,
};

struct Segment {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t file_size;
    uint64_t mem_size;
};

struct Report {
    Container container = Container::Unknown;
    bool valid_elf = false;
    std::vector<std::string> problems;

    uint32_t self_segment_count = 0;
    uint32_t self_encrypted_segments = 0;

    uint8_t os_abi = 0;
    uint16_t type = 0;
    uint16_t machine = 0;
    uint64_t entry = 0;
    std::vector<Segment> segments;

    std::string proc_param_magic;
    uint64_t proc_param_sdk_version = 0;
    bool has_proc_param = false;

    std::string original_filename;
    std::vector<std::string> needed_modules;
    std::vector<std::string> import_libraries;
};

Report Inspect(std::span<const uint8_t> file);

std::string SegmentTypeName(uint32_t type);
std::string ElfTypeName(uint16_t type);
std::string PlatformHint(const Report& report);
std::string Format(const Report& report);

} // namespace ElfInspect
