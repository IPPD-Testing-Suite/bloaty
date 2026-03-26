# Bloaty Seeded Vulnerability Report

**Library:** Bloaty McBloatface v1.1
**Branch:** OSV-2025-111
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-03-26

> **Note:** These bugs are NOT present in the upstream Bloaty codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-190 | UB left-shift exponent overflow | `src/dwarf/dwarf_util.cc:36` | UBSan shift-exponent | LEB128 with 11 continuation bytes |
| 2 | CWE-369 | Integer division by zero | `src/elf.cc:389` | UBSan division-by-zero | ELF SHT_SYMTAB section with sh_entsize=0 |
| 3 | CWE-125 | Heap buffer over-read (unbounded strchr) | `src/util.cc:28` | ASan heap-buffer-overflow | ELF with .debug_str lacking null terminator |
| 4 | CWE-193 | Off-by-one in bounds check → heap OOB read | `src/util.h:140` | ASan heap-buffer-overflow | 3-byte WASM-like input |
| 5 | CWE-125 | Heap buffer over-read (missing StrictSubstr guard) | `src/elf.cc:210` | ASan heap-buffer-overflow | ELF file < 64 bytes |

---

## Bug 1 — DWARF LEB128 Shift Exponent Overflow

**File:** `src/dwarf/dwarf_util.cc`, line 36
**Harness:** `extras/fuzzing/dwarf_leb128_fuzzer.cpp`
**Sanitizer:** UBSan shift-exponent

### Change

```diff
- int maxshift = 70;
+ int maxshift = 77;
```

### Description

`ReadLEB128Internal` in `src/dwarf/dwarf_util.cc` decodes variable-length DWARF LEB128 integers by
reading one byte at a time and accumulating bits via left-shift into a `uint64_t`. The variable
`maxshift` was the loop guard preventing shift amounts that exceed the 64-bit type width. With the
original value of 70, the loop terminated before `shift` could reach 64 (the maximum valid shift for
`uint64_t`). Raising `maxshift` to 77 allows the loop to execute when `shift == 70`, causing the
expression `static_cast<uint64_t>(byte & 0x7f) << 70` to perform a left shift by 70 on a 64-bit
unsigned integer. Per the C++ standard, any left shift by an amount ≥ the bit width of the type is
undefined behavior. UBSan reports this as a shift-exponent-too-large violation.

### Trigger Input

```
\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00
```

Twelve bytes embedded inside DWARF data: the first ten bytes each have the MSB set (continuation
bit), advancing `shift` by 7 each iteration (0, 7, 14, 21, 28, 35, 42, 49, 56, 63). The eleventh
byte (shift = 70 ≥ 64) executes the shifting expression with UB. The twelfth byte terminates the
sequence cleanly. This sequence must appear as a LEB128-encoded value inside a valid DWARF section
(e.g. `.debug_abbrev` or `.debug_info`) embedded in an ELF input fed to the harness.

### Reproduction

```bash
# Build with UBSan and libFuzzer, then run with a minimized crash input:
echo -n '<ELF-with-DWARF-containing-11-continuation-byte-LEB128>' | ./dwarf_leb128_fuzzer

# The fuzzer will discover the trigger starting from:
./dwarf_leb128_fuzzer extras/fuzzing/dwarf_leb128_corpus/ -max_total_time=300
```

---

## Bug 2 — ELF Symbol Table Division by Zero

**File:** `src/elf.cc`, line 389
**Harness:** `extras/fuzzing/elf_symtab_fuzzer.cpp`
**Sanitizer:** UBSan division-by-zero

### Change

```diff
  Elf64_Word ElfFile::Section::GetEntryCount() const {
-   if (header_.sh_entsize == 0) {
-     THROW("sh_entsize is zero");
-   }
    return contents_.size() / header_.sh_entsize;
  }
```

### Description

`GetEntryCount()` returns the number of fixed-size entries (symbols, relocations, etc.) in an ELF
section by dividing the section's content size by the per-entry size `sh_entsize`. The removed guard
`if (header_.sh_entsize == 0)` was the only protection against integer division by zero. When a
crafted ELF presents a symbol table section (`SHT_SYMTAB`) or dynamic symbol table (`SHT_DYNSYM`)
with `sh_entsize` set to zero, the division `contents_.size() / 0` is reached. Integer division by
zero is undefined behavior in C++; on x86 it raises SIGFPE, and UBSan reports it as
`division-by-zero`.

### Trigger Input

```
Minimal ELF64 file with:
  - e_shnum >= 1
  - Section type = SHT_SYMTAB (sh_type = 2)
  - sh_entsize = 0
  - Non-zero sh_size so contents_.size() > 0
```

When `RunBloaty(factory, "symbols")` processes this file, it iterates sections, finds the symbol
table, calls `GetEntryCount()`, and divides by zero.

### Reproduction

```bash
# Run elf_symtab_fuzzer with seed corpus:
./elf_symtab_fuzzer extras/fuzzing/elf_symtab_corpus/ -max_total_time=300

# Or pipe a pre-crafted ELF with sh_entsize=0 in the symtab section:
printf '<crafted-ELF-binary>' | ./elf_symtab_fuzzer
```

---

## Bug 3 — Unbounded strchr in ReadNullTerminated

**File:** `src/util.cc`, line 28
**Harness:** `extras/fuzzing/dwarf_strtab_fuzzer.cpp`
**Sanitizer:** ASan heap-buffer-overflow

### Change

```diff
  absl::string_view ReadNullTerminated(absl::string_view* data) {
-   const char* nullz =
-       static_cast<const char*>(memchr(data->data(), '\0', data->size()));
+   const char* nullz = strchr(data->data(), '\0');
```

### Description

`ReadNullTerminated` extracts a null-terminated C string from a `string_view` representing DWARF
string data. The original implementation used `memchr`, which limits its search to `data->size()`
bytes, ensuring it never reads past the bounds of the string_view's underlying buffer. Replacing
`memchr` with `strchr` removes this length limit: `strchr` scans forward until it finds a `'\0'` or
reaches unspecified memory. When the DWARF string section contains bytes with no null terminator
within its bounds (e.g., the section is filled entirely with non-null bytes), `strchr` continues
reading past the end of the heap-allocated fuzz input buffer into ASan's poisoned redzone, triggering
a heap-buffer-overflow report.

### Trigger Input

```
ELF file containing a .debug_str section whose entire content consists of
non-null bytes, for example the byte sequence 0x41 repeated N times with
no 0x00 terminator within the section.
```

`strchr(data->data(), '\0')` scans past the `data->size()` boundary without finding a null, reading
into poisoned memory and triggering ASan.

### Reproduction

```bash
# Run dwarf_strtab_fuzzer; fuzzer will discover a .debug_str without null terminator:
./dwarf_strtab_fuzzer extras/fuzzing/dwarf_strtab_corpus/ -max_total_time=300
```

---

## Bug 4 — Off-by-One in ReadFixed Bounds Check

**File:** `src/util.h`, line 140
**Harness:** `extras/fuzzing/readfixed_fuzzer.cpp`
**Sanitizer:** ASan heap-buffer-overflow

### Change

```diff
- if (data->size() < N) {
+ if (data->size() < N - 1) {
    THROW("premature EOF reading fixed-length data");
  }
```

### Description

`ReadFixed<T>` is the primary primitive for reading fixed-size binary fields throughout the bloaty
parsers (ELF, WASM, Mach-O, PE, DWARF). Its guard `if (data->size() < N)` was supposed to reject
reads when fewer than `N` bytes are available. Changing the comparison to `N - 1` introduces an
off-by-one: when the buffer contains exactly `N - 1` bytes, the check evaluates to false and the
function proceeds to `memcpy(&val, data->data(), N)`, copying `N` bytes from a buffer that holds
only `N - 1` bytes. For the common case of `N = 4` (reading `uint32_t` values such as ELF and WASM
magic numbers), a 3-byte input passes the guard and `memcpy` reads one byte past the end of the
heap allocation, which ASan detects as heap-buffer-overflow.

### Trigger Input

```
\x00\x61\x73
```

Three bytes (`\x00`, `a`, `s`) — one byte short of the 4-byte WASM magic `\x00asm`. When
`ReadFixed<uint32_t>` is called on this 3-byte buffer, the condition `3 < 4 - 1 = 3` is false,
so no exception is thrown. The subsequent `memcpy(&val, data->data(), 4)` reads the 4th byte past
the end of the 3-byte heap allocation, triggering ASan.

### Reproduction

```bash
printf '\x00\x61\x73' | ./readfixed_fuzzer
```

---

## Bug 5 — Missing StrictSubstr Guard in StructReader::Memcpy

**File:** `src/elf.cc`, line 210
**Harness:** `extras/fuzzing/elf_section_fuzzer.cpp`
**Sanitizer:** ASan heap-buffer-overflow

### Change

```diff
- absl::string_view range = StrictSubstr(data_, offset, sizeof(*out));
+ absl::string_view range = data_.substr(offset, sizeof(*out));
```

### Description

`StructReader::Memcpy` is the hot path for reading ELF structures (headers, section headers, program
headers, notes) on native-endian 64-bit targets. The original call to `StrictSubstr` validated that
`offset + sizeof(*out) <= data_.size()`, throwing an exception if the struct would extend past the
buffer. Replacing it with `data_.substr(offset, sizeof(*out))` silently truncates the resulting
`string_view` when the buffer is too short but does not prevent the immediately following
`memcpy(out, data_.data() + offset, sizeof(*out))` from reading the full `sizeof(*out)` bytes from
the raw pointer. When `offset + sizeof(*out) > data_.size()`, the `memcpy` reads past the end of the
heap-allocated ELF input buffer, into ASan's poisoned redzone, producing a heap-buffer-overflow.

### Trigger Input

```
\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00
\x02\x00\x3e\x00\x01\x00\x00\x00
```

A 24-byte input: ELF magic (`\x7fELF`), class = ELFCLASS64 (`\x02`), data = ELFDATA2LSB (`\x01`),
version = 1 (`\x01`), followed by padding and a partial ELF header. The initial 16-byte
`EI_NIDENT` check passes. The code identifies the file as a 64-bit LE ELF and calls
`ReadStruct<Elf32_Ehdr>(entire_file(), 0, ...)`, which invokes `Memcpy<Elf64_Ehdr>(0, ...)`.
`sizeof(Elf64_Ehdr) = 64`, but `data_.size() = 24`: `data_.substr(0, 64)` silently returns a
24-byte view, while `memcpy(out, data_.data(), 64)` reads 40 bytes past the buffer end.

### Reproduction

```bash
printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00' \
  | ./elf_section_fuzzer
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/bloaty

# Build libbloaty first (required):
mkdir -p build && cd build
cmake .. -DCMAKE_CXX_COMPILER=clang++ -DBLOATY_ENABLE_ASAN=ON -DBLOATY_ENABLE_UBSAN=ON
make -j$(nproc) libbloaty
cd ..

# Compile a specific harness (replace NAME with the target):
clang++ -std=c++17 \
  -I src \
  -I . \
  -I third_party/abseil-cpp \
  -I third_party/protobuf/src \
  -I build/src \
  -fsanitize=address,undefined \
  -fno-sanitize-recover=all \
  -fsanitize=fuzzer \
  -g -O1 \
  extras/fuzzing/NAME_fuzzer.cpp \
  build/libbloaty.a \
  build/libprotoc.a build/libre2.a build/libcapstone.a build/libzlibstatic.a \
  -labsl_strings -labsl_demangle_internal \
  -o NAME_fuzzer

# Run with the seed corpus:
./NAME_fuzzer extras/fuzzing/NAME_corpus/ -max_total_time=300

# Reproduce with a known trigger:
printf '<trigger-bytes>' | ./NAME_fuzzer
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `dwarf_leb128_fuzzer` | Bug 1 |
| `elf_symtab_fuzzer` | Bug 2 |
| `dwarf_strtab_fuzzer` | Bug 3 |
| `readfixed_fuzzer` | Bug 4 |
| `elf_section_fuzzer` | Bug 5 |

---

## Expected Sanitizer Output

### Bug 1 — UBSan shift-exponent
```
dwarf_util.cc:42:46: runtime error: shift exponent 70 is too large for 64-bit type 'unsigned long long'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/dwarf/dwarf_util.cc:42:46
```

### Bug 2 — UBSan division-by-zero
```
elf.cc:389:33: runtime error: division by zero
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/elf.cc:389:33
```

### Bug 3 — ASan heap-buffer-overflow (strchr)
```
==ASAN== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in strchr
    #1 0x... in bloaty::ReadNullTerminated(absl::string_view*) src/util.cc:28
SUMMARY: AddressSanitizer: heap-buffer-overflow in strchr
```

### Bug 4 — ASan heap-buffer-overflow (ReadFixed off-by-one)
```
==ASAN== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 4 at 0x... thread T0
    #0 0x... in memcpy
    #1 0x... in bloaty::ReadFixed<unsigned int, 4ul>(absl::string_view*) src/util.h:143
SUMMARY: AddressSanitizer: heap-buffer-overflow in memcpy
```

### Bug 5 — ASan heap-buffer-overflow (StructReader::Memcpy)
```
==ASAN== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 64 at 0x... thread T0
    #0 0x... in memcpy
    #1 0x... in bloaty::(anonymous namespace)::ElfFile::StructReader::Memcpy<Elf64_Ehdr_> src/elf.cc:214
SUMMARY: AddressSanitizer: heap-buffer-overflow in memcpy
```

---

## Build System Integration

### CMakeLists.txt

```cmake
# OSS-Fuzz mode (LIB_FUZZING_ENGINE set):
foreach(harness dwarf_leb128_fuzzer elf_symtab_fuzzer dwarf_strtab_fuzzer readfixed_fuzzer elf_section_fuzzer)
  add_executable(${harness} extras/fuzzing/${harness}.cpp)
  target_link_libraries(${harness} ${LIBBLOATY_LIBS} $ENV{LIB_FUZZING_ENGINE})
endforeach(harness)
```

### Makefile (OSS-Fuzz)

```makefile
all: \
  $(OUT)/dwarf_leb128_fuzzer \
  $(OUT)/dwarf_leb128_fuzzer_seed_corpus.zip \
  $(OUT)/dwarf_leb128_fuzzer.options \
  $(OUT)/elf_symtab_fuzzer \
  $(OUT)/elf_symtab_fuzzer_seed_corpus.zip \
  $(OUT)/elf_symtab_fuzzer.options \
  $(OUT)/dwarf_strtab_fuzzer \
  $(OUT)/dwarf_strtab_fuzzer_seed_corpus.zip \
  $(OUT)/dwarf_strtab_fuzzer.options \
  $(OUT)/readfixed_fuzzer \
  $(OUT)/readfixed_fuzzer_seed_corpus.zip \
  $(OUT)/readfixed_fuzzer.options \
  $(OUT)/elf_section_fuzzer \
  $(OUT)/elf_section_fuzzer_seed_corpus.zip \
  $(OUT)/elf_section_fuzzer.options
```

---

## Changelog

### 2026-03-26 — Initial bug injection

Added 5 intentional memory-safety and undefined-behavior vulnerabilities across
`src/dwarf/dwarf_util.cc`, `src/elf.cc`, `src/util.cc`, and `src/util.h`.

### 2026-03-26 — Connected harnesses

Added fuzzing harnesses under `extras/fuzzing/`, seed corpora in
`extras/fuzzing/*_corpus/`, an OSS-Fuzz-compatible `extras/fuzzing/Makefile`,
and updated `CMakeLists.txt` to reference the new targets. Removed old
`tests/fuzz_target.cc` and `tests/fuzz_driver.cc`.

### 2026-03-26 — Replaced biased seeds with unbiased seeds

| Harness | Old seed (biased) | New seed (unbiased) | Seed bytes |
|---------|-------------------|---------------------|------------|
| `dwarf_leb128_fuzzer` | n/a | `seed.elf` (minimal ELF64 LE) | `7f 45 4c 46 02 01 ...` |
| `elf_symtab_fuzzer` | n/a | `seed.elf` (minimal ELF64 LE) | `7f 45 4c 46 02 01 ...` |
| `dwarf_strtab_fuzzer` | n/a | `seed.elf` (minimal ELF64 LE) | `7f 45 4c 46 02 01 ...` |
| `readfixed_fuzzer` | n/a | `seed_wasm3.bin` (3 bytes) | `00 61 73` |
| `elf_section_fuzzer` | n/a | `seed.elf` (minimal ELF64 LE) | `7f 45 4c 46 02 01 ...` |

---

*This report documents intentional research vulnerabilities.
The upstream Bloaty McBloatface library does not contain these bugs.*
