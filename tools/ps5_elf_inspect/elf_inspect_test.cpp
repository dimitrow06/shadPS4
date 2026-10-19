// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "elf_inspect.h"

namespace {

int failures = 0;

void Check(bool condition, const std::string& what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << '\n';
        failures++;
    }
}

template <typename T>
void Put(std::vector<uint8_t>& out, size_t offset, T value) {
    if (out.size() < offset + sizeof(T)) {
        out.resize(offset + sizeof(T));
    }
    std::memcpy(out.data() + offset, &value, sizeof(T));
}

void PutPhdr(std::vector<uint8_t>& out, size_t index, uint32_t type, uint64_t offset,
             uint64_t vaddr, uint64_t size) {
    const size_t base = 64 + index * 56;
    Put<uint32_t>(out, base, type);
    Put<uint32_t>(out, base + 4, 4);
    Put<uint64_t>(out, base + 8, offset);
    Put<uint64_t>(out, base + 16, vaddr);
    Put<uint64_t>(out, base + 32, size);
    Put<uint64_t>(out, base + 40, size);
}

std::vector<uint8_t> MakeElf(uint16_t type, const char proc_magic[4]) {
    std::vector<uint8_t> elf(0x400, 0);
    std::memcpy(elf.data(),
                "\x7f"
                "ELF",
                4);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[7] = 9;
    Put<uint16_t>(elf, 16, type);
    Put<uint16_t>(elf, 18, 62);
    Put<uint32_t>(elf, 20, 1);
    Put<uint64_t>(elf, 24, 0x1000);
    Put<uint64_t>(elf, 32, 64);
    Put<uint16_t>(elf, 52, 64);
    Put<uint16_t>(elf, 54, 56);
    Put<uint16_t>(elf, 56, 4);

    const size_t dyn = 0x200;
    const size_t dynlib = 0x300;
    const size_t proc = 0x380;
    PutPhdr(elf, 0, 0x1, 0, 0, 0x400);
    PutPhdr(elf, 1, 0x2, dyn, 0, 0x60);
    PutPhdr(elf, 2, 0x61000000, dynlib, 0, 0x40);
    PutPhdr(elf, 3, 0x61000001, proc, 0, 0x20);

    const char strings[] = "\0libkernel\0libSceVideoOut\0eboot.bin\0";
    std::memcpy(elf.data() + dynlib, strings, sizeof(strings));
    Put<int64_t>(elf, dyn + 0x00, 0x61000035);
    Put<uint64_t>(elf, dyn + 0x08, 0);
    Put<int64_t>(elf, dyn + 0x10, 0x61000037);
    Put<uint64_t>(elf, dyn + 0x18, sizeof(strings));
    Put<int64_t>(elf, dyn + 0x20, 0x6100000f);
    Put<uint64_t>(elf, dyn + 0x28, 0x0001'0101'0000'0001ull);
    Put<int64_t>(elf, dyn + 0x30, 0x61000015);
    Put<uint64_t>(elf, dyn + 0x38, 0x0002'0001'0000'000bull);
    Put<int64_t>(elf, dyn + 0x40, 0x61000009);
    Put<uint64_t>(elf, dyn + 0x48, 26);

    Put<uint64_t>(elf, proc, 0x40);
    std::memcpy(elf.data() + proc + 8, proc_magic, 4);
    Put<uint64_t>(elf, proc + 16, 0x09008001ull);
    return elf;
}

void TestPs4Executable() {
    const auto report = ElfInspect::Inspect(MakeElf(0xfe10, "ORBI"));
    Check(report.valid_elf, "PS4 ELF is valid");
    Check(report.container == ElfInspect::Container::Elf, "container is ELF");
    Check(report.segments.size() == 4, "four segments parsed");
    Check(report.proc_param_magic == "ORBI", "proc param magic");
    Check(report.proc_param_sdk_version == 0x09008001ull, "sdk version");
    Check(report.needed_modules == std::vector<std::string>{"libkernel"}, "needed module");
    Check(report.import_libraries == std::vector<std::string>{"libSceVideoOut"}, "import lib");
    Check(report.original_filename == "eboot.bin", "original filename");
    Check(ElfInspect::PlatformHint(report).find("PS4") != std::string::npos, "PS4 hint");
}

void TestUnknownProcParam() {
    const auto report = ElfInspect::Inspect(MakeElf(0xfe10, "XXXX"));
    Check(report.valid_elf, "unknown proc param ELF is valid");
    Check(ElfInspect::PlatformHint(report).find("possibly PS5") != std::string::npos,
          "unknown magic hints PS5");
}

void TestSelfIsNotDecrypted() {
    const auto elf = MakeElf(0xfe10, "ORBI");
    std::vector<uint8_t> self(64, 0);
    Put<uint32_t>(self, 0, 0x1D3D154Fu);
    Put<uint16_t>(self, 24, 1);
    Put<uint64_t>(self, 32, 0x2);
    self.insert(self.end(), elf.begin(), elf.end());

    const auto report = ElfInspect::Inspect(self);
    Check(report.container == ElfInspect::Container::Self, "container is SELF");
    Check(report.self_encrypted_segments == 1, "encrypted segment counted");
    Check(report.valid_elf, "embedded ELF header parsed");
    Check(report.needed_modules.empty(), "SELF contents are not parsed");
    Check(ElfInspect::PlatformHint(report).find("does not decrypt") != std::string::npos,
          "SELF hint");
}

void TestPlainHomebrewElf() {
    auto elf = MakeElf(0x3, "ORBI");
    Put<uint16_t>(elf, 56, 1);
    const auto report = ElfInspect::Inspect(elf);
    Check(report.valid_elf, "plain ELF is valid");
    Check(ElfInspect::PlatformHint(report).find("homebrew") != std::string::npos, "homebrew hint");
}

void TestRejectsGarbage() {
    const std::vector<uint8_t> garbage(100, 0xAB);
    const auto report = ElfInspect::Inspect(garbage);
    Check(!report.valid_elf, "garbage rejected");
    Check(report.container == ElfInspect::Container::Unknown, "garbage container unknown");
}

void TestTruncatedInputsDoNotCrash() {
    const auto elf = MakeElf(0xfe10, "ORBI");
    for (size_t size = 0; size <= elf.size(); size++) {
        const auto report = ElfInspect::Inspect(std::span(elf.data(), size));
        ElfInspect::Format(report);
    }
}

} // namespace

int main() {
    TestPs4Executable();
    TestUnknownProcParam();
    TestSelfIsNotDecrypted();
    TestPlainHomebrewElf();
    TestRejectsGarbage();
    TestTruncatedInputsDoNotCrash();
    if (failures) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "all checks passed\n";
    return 0;
}
