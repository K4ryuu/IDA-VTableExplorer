# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.1] - 2025-11-18

### Changed

**Annotation Format**

- Updated vtable entry comments to `"index: X | offset: Y"` format (includes both virtual function index and byte offset)
- Removed function-level comments from decompiled code (assembly-only annotation now)

**Function Detection**

- Enhanced function pointer validation with name-based trust (accepts IDA auto-generated names: `sub_*`, `nullsub_*`, `j_*`, `*_vfunc_*`)
- Increased invalid entry tolerance from 2 to 5 consecutive entries for better vtable scanning

---

## [1.0.0] - 2025-11-16

### Added

**Platform Support**

- ► IDA Pro 9.x with modern SDK APIs
- ► macOS ARM64 (Apple Silicon M1/M2/M3)
- ► macOS Intel x64
- ► Linux x64
- ► Windows x64
- ► Docker multi-platform build system

**Core Features**

- Symbol-based vtable detection (Linux/GCC + Windows/MSVC)
- Automatic class name extraction from mangled symbols
- Virtual function index annotation (0-based indexing)
- Native IDA chooser interface with searchable vtable list
- Smart RTTI offset detection (Linux: +2, Windows: 0)
- Boundary detection (stops at next vtable or invalid pointers)

**Symbol Detection**

- `_ZTV*` pattern matching (Linux/GCC vtables)
- `??_7*@@6B@` pattern matching (Windows/MSVC vftables)
- Fallback patterns: `*vftable*`, `*vtbl*`
- Itanium C++ name mangling parser
- IDA demangler integration

**Annotation System**

- Automatic index annotation (`vtable index #0`, `#1`, etc.)
- Function-level comments (`vtable index: 0`)
- Vtable entry comments (`vtable index #0`)
- 0-based indexing (C++ standard compliant)
- RTTI/typeinfo pointer skipping

**User Interface**

- Context menu integration (right-click → VTable Explorer)
- Platform-specific hotkeys (⌘⇧V / Ctrl+Shift+V)
- Searchable vtable list (2000+ entries support)
- One-click annotation and navigation
- Info dialog with annotation summary

### Technical Implementation

**VTable Detection Strategy**

- Symbol enumeration via `get_nlist_size()` / `get_nlist_ea()`
- Mangled name parsing with length-prefix extraction
- Nested namespace handling (`_ZTVN...E` format)
- `_ptr` suffix stripping (IDA symbol decoration)

**Class Name Extraction**

- Primary: IDA `demangle_name()` API
- Fallback: Manual Itanium C++ name parsing
- Simple names: `_ZTV<len><name>` extraction
- Complex names: Nested component extraction

**Offset Detection**

- Auto-detection of first valid function pointer
- Linux default: offset +2 (after offset-to-top + RTTI)
- Windows default: offset 0 (immediate vfunc start)
- Validation: executable segment + function prologue checks

**Annotation Logic**

- Separate `vfunc_index` counter (not loop counter)
- Skips invalid/typeinfo pointers without breaking index
- Consecutive invalid limit (max 2)
- Boundary detection (next vtable or unmapped memory)

### Build System

- Docker multi-stage builds (Linux, Windows, macOS ARM64, macOS x64)
- Single `make build` command for all platforms
- Cross-compilation via osxcross and mingw-w64

---

**Repository**: [K4ryuu/IDA-VTableExplorer](https://github.com/K4ryuu/IDA-VTableExplorer)
