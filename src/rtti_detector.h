#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include "vtable_utils.h"

namespace rtti_detector {

using vtable_utils::get_ptr_size;
using vtable_utils::read_ptr;

struct RTTIConfig {
    bool is_msvc = false;
    bool use_64bit_ptrs = false;
    int rtti_offset = -8;
    bool detected = false;
};

static RTTIConfig g_config;

// Format detection
inline bool is_pe_file() {
    char ftype[64];
    return get_file_type_name(ftype, sizeof(ftype)) && strstr(ftype, "PE");
}

inline bool is_elf_file() {
    char ftype[64];
    return get_file_type_name(ftype, sizeof(ftype)) && strstr(ftype, "ELF");
}

inline bool has_msvc_mangling(ea_t addr) {
    qstring name;
    return get_name(&name, addr) && name.length() >= 4 && strncmp(name.c_str(), "??_7", 4) == 0;
}

inline bool has_gcc_mangling(ea_t addr) {
    qstring name;
    return get_name(&name, addr) && name.length() >= 4 && strncmp(name.c_str(), "_ZTV", 4) == 0;
}

// MSVC COL validation
inline bool validate_msvc_col(ea_t col_addr) {
    if (!is_mapped(col_addr)) return false;

    uint32 sig = get_dword(col_addr);
    if (sig > 2) return false;

    const int ptr_size = get_ptr_size();
    int32 type_rva = get_dword(col_addr + 12);
    int32 class_rva = get_dword(col_addr + 16);

    ea_t type_addr, class_addr;
    if (ptr_size == 8) {
        ea_t base = get_imagebase();
        if (base == BADADDR) return false;
        type_addr = base + type_rva;
        class_addr = base + class_rva;
    } else {
        type_addr = type_rva;
        class_addr = class_rva;
    }

    if (!is_mapped(type_addr) || !is_mapped(class_addr)) return false;
    if (get_dword(class_addr) != 0) return false;
    if (get_dword(class_addr + 8) > 64) return false;

    return true;
}

// GCC typeinfo validation
inline bool validate_gcc_typeinfo(ea_t ti_addr) {
    if (!is_mapped(ti_addr)) return false;

    ea_t vtbl = read_ptr(ti_addr);
    if (!is_mapped(vtbl)) return false;

    ea_t name = read_ptr(ti_addr + get_ptr_size());
    if (!is_mapped(name)) return false;

    char prefix[5] = {0};
    for (int i = 0; i < 4; i++) {
        prefix[i] = get_byte(name + i);
        if (!isprint(prefix[i]) && prefix[i] != '_') return false;
    }
    return strcmp(prefix, "_ZTS") == 0;
}

// MSVC x64: detect if using 64-bit pointers or 32-bit RVAs
inline bool detect_msvc_64bit_ptr_format(ea_t vtable) {
    ea_t base = get_imagebase();
    if (base == BADADDR) return true;

    ea_t ptr64 = get_qword(vtable - 8);
    if (is_mapped(ptr64) && validate_msvc_col(ptr64)) return true;

    uint32 rva = get_dword(vtable - 8);
    if (is_mapped(base + rva) && validate_msvc_col(base + rva)) return false;

    return true;
}

// Find RTTI offset by probing common locations
inline int detect_rtti_offset(ea_t vtable, bool is_msvc) {
    static const int offsets[] = {-8, -16, 8, 0, 16, -24, 24};
    const int ptr_size = get_ptr_size();

    for (int off : offsets) {
        ea_t probe = vtable + off;
        if (!is_mapped(probe)) continue;

        if (is_msvc) {
            ea_t col = (ptr_size == 8) ? get_qword(probe) : get_dword(probe);
            if (is_mapped(col) && validate_msvc_col(col)) return off;

            if (ptr_size == 8) {
                ea_t base = get_imagebase();
                if (base != BADADDR) {
                    col = base + get_dword(probe);
                    if (is_mapped(col) && validate_msvc_col(col)) return off;
                }
            }
        } else {
            ea_t ti = read_ptr(probe);
            if (is_mapped(ti) && validate_gcc_typeinfo(ti)) return off;
        }
    }
    return -8;
}

// Main detection
inline RTTIConfig auto_detect(ea_t vtable) {
    RTTIConfig cfg;
    cfg.is_msvc = has_msvc_mangling(vtable) || (!has_gcc_mangling(vtable) && is_pe_file());

    if (cfg.is_msvc && get_ptr_size() == 8)
        cfg.use_64bit_ptrs = detect_msvc_64bit_ptr_format(vtable);

    cfg.rtti_offset = detect_rtti_offset(vtable, cfg.is_msvc);
    cfg.detected = true;
    return cfg;
}

inline const RTTIConfig& get_config(ea_t vtable) {
    if (!g_config.detected) g_config = auto_detect(vtable);
    return g_config;
}

inline void reset_config() { g_config = RTTIConfig(); }

} // namespace rtti_detector
