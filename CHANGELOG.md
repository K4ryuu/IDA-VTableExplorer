# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.2.1] - 2025-12-21

### Added

- **RTTI Auto-Detection**: Automatic MSVC vs GCC/Itanium format detection based on file type and symbol mangling
- **Intermediate Class Support**: Detect and display compiler-inlined classes that exist in RTTI chain but have no vtable symbol
- **Inheritance Graph Enhancement**: Intermediate classes shown with proper parent-child connections and "uses [ParentVTable]" info
- **MSVC x64 Pointer Format Detection**: Auto-detect 64-bit absolute pointers vs 32-bit RVA format in Complete Object Locator

### Fixed

- **Nested Class Name Normalization**: MSVC nested classes now properly display as `Outer::Inner` instead of `Outer@Inner`
- **Graph Edge Logic**: Fixed intermediate class connections - parent→intermediate→child chain displays correctly
- **Class Name Validation**: Relaxed validation to support more edge cases

### Improved

- **Code Cleanup**: Compact comments, renamed functions, removed redundant code
- **Chooser Simplification**: Removed unused Insert/Delete options from VTable list
- **Buffer Sizes**: Increased limits for longer class names and RTTI strings

---

## [1.2.0] - 2025-12-19 - Check README.md

### Added

-  Graph-based inheritance visualization with interactive navigation
-  RTTI parser for automatic inheritance detection (GCC/MSVC formats)
-  Comparison view with override detection and filtering
-  Base class and derived count columns
-  Keyboard shortcuts (Cmd/Ctrl+Shift+V/T/C)

### Fixed

-  Compiler-specific warning flags (GCC vs Clang)
-  macOS deployment target (12.0 to match IDA SDK)
-  All platforms build with 0 warnings

---

## [1.1.0] - 2025-12-02

### Added

**Function Browser**

-  New `Del` key action: Browse all functions in a vtable
-  Secondary chooser window showing function index, address, name, and status
-  Jump to any function with `Enter` key
-  Pure virtual functions highlighted in red

**Pure Virtual Detection**

-  Automatic detection of `__cxa_pure_virtual`, `_purecall`, and `purevirt` symbols
-  Abstract classes marked with `[abstract]` suffix and distinct color
-  Function count shows pure virtual breakdown: `26 (3 pv)`

**Annotate All**

-  New `Ins` key action: Annotate all vtables at once
-  Progress indicator with cancel support
-  Summary dialog showing total vtables and functions processed

**UI Improvements**

-  New "Functions" column showing function count per vtable
-  Color coding: abstract classes in light blue, pure virtuals in red
-  Dockable tab instead of modal window
-  Singleton chooser - reopening brings back the same tab with cached data
-  Refresh action to rescan vtables

### Optimized

-  Cached vtable data for instant reopening
-  Binary search for vtable boundary detection
-  Unified scanner template eliminates duplicate code

---

## [1.0.2] - 2025-11-20

### Fixed

-  Buffer overrun protection in `demangle_msvc_name()` for malformed MSVC symbols
-  Exception handling around `find_vtables()` to prevent crashes

### Removed

-  Windows Docker build (MinGW has ABI incompatibility with MSVC for C++ virtual functions)

---

## [1.0.1] - 2025-11-18

### Changed

**Annotation Format**

-  Updated vtable entry comments to `"index: X | offset: Y"` format (includes both virtual function index and byte offset)
-  Removed function-level comments from decompiled code (assembly-only annotation now)

**Function Detection**

-  Enhanced function pointer validation with name-based trust (accepts IDA auto-generated names: `sub_*`, `nullsub_*`, `j_*`, `*_vfunc_*`)
-  Increased invalid entry tolerance from 2 to 5 consecutive entries for better vtable scanning

---

## [1.0.0] - 2025-11-16

### Added

-  Symbol-based vtable detection (`_ZTV*` for Linux/GCC, `??_7*` for Windows/MSVC)
-  Automatic class name extraction from mangled symbols
-  Virtual function index annotation with byte offsets
-  Native IDA chooser with searchable vtable list
-  Smart RTTI offset detection
-  Context menu and hotkey support (⌘⇧V / Ctrl+Shift+V)
-  Multi-platform support: IDA Pro 9.x on Linux, Windows, macOS (ARM64 + x64)
-  Docker-based cross-compilation build system

---

**Repository**: [K4ryuu/IDA-VTableExplorer](https://github.com/K4ryuu/IDA-VTableExplorer)
