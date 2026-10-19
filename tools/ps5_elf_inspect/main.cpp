// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include "elf_inspect.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ps5_elf_inspect <eboot.bin | module.prx | payload.elf>\n";
        return 2;
    }
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open " << argv[1] << '\n';
        return 2;
    }
    const std::vector<uint8_t> data{std::istreambuf_iterator<char>(file), {}};
    const auto report = ElfInspect::Inspect(data);
    std::cout << ElfInspect::Format(report);
    return report.valid_elf ? 0 : 1;
}
