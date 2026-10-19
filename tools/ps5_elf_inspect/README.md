<!--
SPDX-FileCopyrightText: 2026 shadPS4 Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# ps5_elf_inspect

A standalone command-line tool that describes a PS4/PS5 executable or module so we can
learn how PS5 binaries differ from PS4 ones before changing the loader.

It reports:

- whether the file is a plain ELF or a signed/encrypted SELF container;
- the ELF type, OS ABI and entry point;
- every program header, including the SCE-specific ones;
- the process param magic and SDK version (`ORBI` means PS4);
- the needed modules and imported libraries from the dynamic section.

It never decrypts anything. A SELF has to be decrypted on your own console first.

## Build and run

```sh
cmake -S tools/ps5_elf_inspect -B build/elf_inspect
cmake --build build/elf_inspect
ctest --test-dir build/elf_inspect
build/elf_inspect/ps5_elf_inspect path/to/eboot.bin
```
