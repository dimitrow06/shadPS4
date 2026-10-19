// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "elf_inspect.h"

#include <cstring>
#include <optional>
#include <sstream>

namespace ElfInspect {

namespace {

constexpr uint32_t SelfMagic = 0x1D3D154Fu;
constexpr size_t SelfHeaderSize = 32;
constexpr size_t SelfSegmentSize = 32;
constexpr size_t ElfHeaderSize = 64;
constexpr size_t ProgramHeaderSize = 56;
constexpr size_t DynamicEntrySize = 16;

constexpr uint8_t OsAbiFreeBsd = 9;
constexpr uint16_t MachineX86_64 = 62;

constexpr uint32_t PtLoad = 0x1;
constexpr uint32_t PtDynamic = 0x2;
constexpr uint32_t PtSceDynlibData = 0x61000000;
constexpr uint32_t PtSceProcParam = 0x61000001;

constexpr int64_t DtNull = 0;
constexpr int64_t DtNeeded = 1;
constexpr int64_t DtStrtab = 5;
constexpr int64_t DtSceOriginalFilename = 0x61000009;
constexpr int64_t DtSceNeededModule = 0x6100000f;
constexpr int64_t DtSceImportLib = 0x61000015;
constexpr int64_t DtSceStrtab = 0x61000035;
constexpr int64_t DtSceStrsz = 0x61000037;

template <typename T>
std::optional<T> Read(std::span<const uint8_t> data, uint64_t offset) {
    if (offset > data.size() || data.size() - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return value;
}

std::span<const uint8_t> Slice(std::span<const uint8_t> data, uint64_t offset, uint64_t size) {
    if (offset > data.size() || data.size() - offset < size) {
        return {};
    }
    return data.subspan(offset, size);
}

std::string ReadString(std::span<const uint8_t> table, uint64_t offset) {
    if (offset >= table.size()) {
        return {};
    }
    const auto* begin = reinterpret_cast<const char*>(table.data() + offset);
    return std::string(begin, strnlen(begin, table.size() - offset));
}

std::optional<uint64_t> VaddrToOffset(const Report& report, uint64_t vaddr) {
    for (const auto& segment : report.segments) {
        if (segment.type == PtLoad && vaddr >= segment.vaddr &&
            vaddr - segment.vaddr < segment.file_size) {
            return segment.offset + (vaddr - segment.vaddr);
        }
    }
    return std::nullopt;
}

const Segment* FindSegment(const Report& report, uint32_t type) {
    for (const auto& segment : report.segments) {
        if (segment.type == type) {
            return &segment;
        }
    }
    return nullptr;
}

void InspectSelf(std::span<const uint8_t> file, Report& report, uint64_t& elf_offset) {
    const auto segment_count = Read<uint16_t>(file, 24).value_or(0);
    report.self_segment_count = segment_count;
    for (uint32_t i = 0; i < segment_count; i++) {
        const auto flags = Read<uint64_t>(file, SelfHeaderSize + i * SelfSegmentSize);
        if (!flags) {
            report.problems.push_back("SELF segment table is truncated");
            break;
        }
        if (*flags & 2) {
            report.self_encrypted_segments++;
        }
    }
    elf_offset = SelfHeaderSize + uint64_t{segment_count} * SelfSegmentSize;
}

void InspectProcParam(std::span<const uint8_t> file, Report& report) {
    const auto* segment = FindSegment(report, PtSceProcParam);
    if (!segment) {
        return;
    }
    const auto magic = Slice(file, segment->offset + 8, 4);
    if (magic.empty()) {
        report.problems.push_back("PT_SCE_PROCPARAM points outside the file");
        return;
    }
    report.has_proc_param = true;
    for (const auto byte : magic) {
        report.proc_param_magic += (byte >= 0x20 && byte < 0x7f) ? static_cast<char>(byte) : '?';
    }
    report.proc_param_sdk_version = Read<uint64_t>(file, segment->offset + 16).value_or(0);
}

void InspectDynamic(std::span<const uint8_t> file, Report& report) {
    const auto* dynamic = FindSegment(report, PtDynamic);
    if (!dynamic) {
        return;
    }
    const auto entries = Slice(file, dynamic->offset, dynamic->file_size);
    if (entries.empty()) {
        report.problems.push_back("PT_DYNAMIC points outside the file");
        return;
    }

    const auto* dynlib = FindSegment(report, PtSceDynlibData);
    std::span<const uint8_t> strings;
    uint64_t sce_strtab = 0;
    uint64_t sce_strsz = 0;
    std::optional<uint64_t> plain_strtab;

    for (uint64_t pos = 0; pos + DynamicEntrySize <= entries.size(); pos += DynamicEntrySize) {
        const auto tag = *Read<int64_t>(entries, pos);
        const auto value = *Read<uint64_t>(entries, pos + 8);
        if (tag == DtNull) {
            break;
        }
        if (tag == DtSceStrtab) {
            sce_strtab = value;
        } else if (tag == DtSceStrsz) {
            sce_strsz = value;
        } else if (tag == DtStrtab) {
            plain_strtab = VaddrToOffset(report, value);
        }
    }

    if (dynlib && sce_strsz) {
        strings = Slice(file, dynlib->offset + sce_strtab, sce_strsz);
    } else if (plain_strtab && *plain_strtab < file.size()) {
        strings = file.subspan(*plain_strtab);
    }
    if (strings.empty()) {
        report.problems.push_back("dynamic string table not found");
        return;
    }

    for (uint64_t pos = 0; pos + DynamicEntrySize <= entries.size(); pos += DynamicEntrySize) {
        const auto tag = *Read<int64_t>(entries, pos);
        const auto value = *Read<uint64_t>(entries, pos + 8);
        const auto name_offset = value & 0xFFFFFFFFu;
        if (tag == DtNull) {
            break;
        }
        switch (tag) {
        case DtNeeded:
            report.needed_modules.push_back(ReadString(strings, value));
            break;
        case DtSceNeededModule:
            report.needed_modules.push_back(ReadString(strings, name_offset));
            break;
        case DtSceImportLib:
            report.import_libraries.push_back(ReadString(strings, name_offset));
            break;
        case DtSceOriginalFilename:
            report.original_filename = ReadString(strings, value);
            break;
        default:
            break;
        }
    }
}

} // namespace

Report Inspect(std::span<const uint8_t> file) {
    Report report;
    uint64_t elf_offset = 0;

    if (Read<uint32_t>(file, 0) == SelfMagic) {
        report.container = Container::Self;
        InspectSelf(file, report, elf_offset);
    }

    const auto header = Slice(file, elf_offset, ElfHeaderSize);
    if (header.empty() || std::memcmp(header.data(),
                                      "\x7f"
                                      "ELF",
                                      4) != 0) {
        report.problems.push_back("no ELF header found");
        return report;
    }
    if (report.container == Container::Unknown) {
        report.container = Container::Elf;
    }
    if (header[4] != 2 || header[5] != 1) {
        report.problems.push_back("not a 64-bit little-endian ELF");
        return report;
    }

    report.os_abi = header[7];
    report.type = *Read<uint16_t>(header, 16);
    report.machine = *Read<uint16_t>(header, 18);
    report.entry = *Read<uint64_t>(header, 24);
    const auto phoff = *Read<uint64_t>(header, 32);
    const auto phentsize = *Read<uint16_t>(header, 54);
    const auto phnum = *Read<uint16_t>(header, 56);

    if (report.machine != MachineX86_64) {
        report.problems.push_back("machine is not x86-64");
    }
    if (report.os_abi != OsAbiFreeBsd) {
        report.problems.push_back("OS ABI is not FreeBSD");
    }
    if (phnum && phentsize != ProgramHeaderSize) {
        report.problems.push_back("unexpected program header size");
        return report;
    }

    for (uint16_t i = 0; i < phnum; i++) {
        const auto ph =
            Slice(file, elf_offset + phoff + uint64_t{i} * ProgramHeaderSize, ProgramHeaderSize);
        if (ph.empty()) {
            report.problems.push_back("program header table is truncated");
            break;
        }
        report.segments.push_back({
            .type = *Read<uint32_t>(ph, 0),
            .flags = *Read<uint32_t>(ph, 4),
            .offset = *Read<uint64_t>(ph, 8),
            .vaddr = *Read<uint64_t>(ph, 16),
            .file_size = *Read<uint64_t>(ph, 32),
            .mem_size = *Read<uint64_t>(ph, 40),
        });
    }

    report.valid_elf = report.problems.empty();

    if (report.container == Container::Self) {
        return report;
    }
    InspectProcParam(file, report);
    InspectDynamic(file, report);
    return report;
}

std::string SegmentTypeName(uint32_t type) {
    switch (type) {
    case 0x0:
        return "NULL";
    case 0x1:
        return "LOAD";
    case 0x2:
        return "DYNAMIC";
    case 0x3:
        return "INTERP";
    case 0x4:
        return "NOTE";
    case 0x6:
        return "PHDR";
    case 0x7:
        return "TLS";
    case 0x60000000:
        return "SCE_RELA";
    case 0x61000000:
        return "SCE_DYNLIBDATA";
    case 0x61000001:
        return "SCE_PROCPARAM";
    case 0x61000002:
        return "SCE_MODULE_PARAM";
    case 0x61000010:
        return "SCE_RELRO";
    case 0x6474e550:
        return "GNU_EH_FRAME";
    case 0x6474e551:
        return "GNU_STACK";
    case 0x6474e552:
        return "GNU_RELRO";
    case 0x6fffff00:
        return "SCE_COMMENT";
    case 0x6fffff01:
        return "SCE_LIBVERSION";
    default: {
        std::ostringstream out;
        out << "0x" << std::hex << type;
        return out.str();
    }
    }
}

std::string ElfTypeName(uint16_t type) {
    switch (type) {
    case 0x2:
        return "EXEC";
    case 0x3:
        return "DYN";
    case 0xfe00:
        return "SCE_EXEC";
    case 0xfe0c:
        return "SCE_STUBLIB";
    case 0xfe10:
        return "SCE_DYNEXEC";
    case 0xfe18:
        return "SCE_DYNAMIC";
    default: {
        std::ostringstream out;
        out << "0x" << std::hex << type;
        return out.str();
    }
    }
}

std::string PlatformHint(const Report& report) {
    if (report.container == Container::Self) {
        return "Signed/encrypted SELF. Decrypt it on your own console first; this tool does not "
               "decrypt.";
    }
    if (!report.valid_elf) {
        return "Not a loadable PS4/PS5 ELF.";
    }
    if (report.type == 0x2 || report.type == 0x3) {
        return "Plain FreeBSD ELF, typical for homebrew payloads (e.g. ps5-payload-sdk). The "
               "shadPS4 loader does not accept this ELF type yet.";
    }
    if (report.proc_param_magic == "ORBI") {
        return "PS4 (Orbis) executable.";
    }
    if (report.has_proc_param) {
        return "Unknown process param magic '" + report.proc_param_magic +
               "', possibly PS5 (Prospero). Please report it.";
    }
    return "SCE module without process params (library/PRX).";
}

std::string Format(const Report& report) {
    std::ostringstream out;
    out << "Container:   "
        << (report.container == Container::Self  ? "SELF"
            : report.container == Container::Elf ? "ELF"
                                                 : "unknown")
        << '\n';
    if (report.container == Container::Self) {
        out << "SELF segs:   " << report.self_segment_count << " ("
            << report.self_encrypted_segments << " encrypted)\n";
    }
    if (report.container != Container::Unknown) {
        out << "Type:        " << ElfTypeName(report.type) << '\n';
        out << "OS ABI:      " << int{report.os_abi} << '\n';
        out << "Entry:       0x" << std::hex << report.entry << std::dec << '\n';
    }
    if (report.has_proc_param) {
        out << "ProcParam:   '" << report.proc_param_magic << "' sdk 0x" << std::hex
            << report.proc_param_sdk_version << std::dec << '\n';
    }
    if (!report.original_filename.empty()) {
        out << "Filename:    " << report.original_filename << '\n';
    }
    out << "Platform:    " << PlatformHint(report) << '\n';

    if (!report.segments.empty()) {
        out << "\nSegments:\n";
        for (const auto& s : report.segments) {
            out << "  " << SegmentTypeName(s.type) << " off=0x" << std::hex << s.offset
                << " vaddr=0x" << s.vaddr << " filesz=0x" << s.file_size << " memsz=0x"
                << s.mem_size << " flags=0x" << s.flags << std::dec << '\n';
        }
    }
    if (!report.needed_modules.empty()) {
        out << "\nNeeded modules:\n";
        for (const auto& name : report.needed_modules) {
            out << "  " << name << '\n';
        }
    }
    if (!report.import_libraries.empty()) {
        out << "\nImported libraries:\n";
        for (const auto& name : report.import_libraries) {
            out << "  " << name << '\n';
        }
    }
    if (!report.problems.empty()) {
        out << "\nProblems:\n";
        for (const auto& problem : report.problems) {
            out << "  " << problem << '\n';
        }
    }
    return out.str();
}

} // namespace ElfInspect
