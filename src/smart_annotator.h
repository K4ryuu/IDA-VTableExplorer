#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <auto.hpp>
#include <vector>
#include <algorithm>
#include "vtable_utils.h"
#include "rtti_detector.h"

namespace smart_annotator {

using vtable_utils::get_ptr_size;
using vtable_utils::read_ptr;
using vtable_utils::OPCODE_PUSH_RBP;
using vtable_utils::OPCODE_REX_W;
using vtable_utils::OPCODE_REX;
using vtable_utils::OPCODE_REX_B;

inline int detect_vfunc_start_offset(ea_t vtable_addr, bool) {
    using namespace vtable_utils;

    const auto& config = rtti_detector::get_config(vtable_addr);
    if (config.is_msvc) return 0;

    const int ptr_size = get_ptr_size();
    for (int i = 0; i < MAX_VFUNC_SEARCH_DEPTH; ++i) {
        ea_t entry = vtable_addr + (i * ptr_size);
        if (!is_mapped(entry)) continue;

        segment_t* seg = getseg(read_ptr(entry));
        if (seg && (seg->perm & SEGPERM_EXEC)) return i;
    }

    // GCC/Itanium: [offset-to-top, typeinfo*, vfuncs...]
    return (config.rtti_offset < 0) ? 2 : DEFAULT_VFUNC_START_OFFSET;
}

inline bool is_pure_virtual(ea_t func) {
    if (!func || func == BADADDR) return false;
    qstring name;
    if (!get_name(&name, func)) return false;
    return name.find("__cxa_pure_virtual") != qstring::npos ||
           name.find("_purecall") != qstring::npos ||
           name.find("purevirt") != qstring::npos;
}

inline bool is_typeinfo(ea_t ptr) {
    qstring name;
    return get_name(&name, ptr) &&
           (name.find("_ZTI") != qstring::npos || name.find("typeinfo") != qstring::npos);
}

inline bool is_valid_func_ptr(ea_t addr) {
    if (!addr || addr == BADADDR || !is_mapped(addr)) return false;

    segment_t* seg = getseg(addr);
    if (!seg || !(seg->perm & SEGPERM_EXEC)) return false;
    if (is_code(get_flags(addr))) return true;

    qstring name;
    if (get_name(&name, addr)) {
        const char* n = name.c_str();
        if (strncmp(n, "sub_", 4) == 0 || strncmp(n, "nullsub_", 8) == 0 ||
            strncmp(n, "j_", 2) == 0 || strstr(n, "_vfunc_"))
            return true;
    }

    uint8 b = get_byte(addr);
    return b == OPCODE_PUSH_RBP || b == OPCODE_REX_W || b == OPCODE_REX || b == OPCODE_REX_B;
}

inline ea_t find_next_vtable(ea_t current, const std::vector<ea_t>& sorted) {
    auto it = std::upper_bound(sorted.begin(), sorted.end(), current);
    return (it != sorted.end()) ? *it : BADADDR;
}

struct VTableEntry {
    ea_t entry_addr;
    ea_t func_ptr;
    int index;
    bool is_pure_virtual;
};

struct VTableStats {
    int func_count = 0;
    int pure_virtual_count = 0;
};

template<bool collect_entries, bool annotate>
inline VTableStats scan_vtable(
    ea_t vtable_addr,
    bool is_windows,
    const std::vector<ea_t>& sorted_vtables,
    std::vector<VTableEntry>* out_entries = nullptr)
{
    using namespace vtable_utils;

    VTableStats stats;
    const int ptr_size = get_ptr_size();
    const int start_offset = detect_vfunc_start_offset(vtable_addr, is_windows);
    const ea_t next_vtable = find_next_vtable(vtable_addr, sorted_vtables);

    int max_check = MAX_VTABLE_ENTRIES;
    if (next_vtable != BADADDR && next_vtable > vtable_addr)
        max_check = std::min(max_check, (int)((next_vtable - vtable_addr) / ptr_size));

    int consecutive_invalid = 0;
    int vfunc_index = 0;
    char cmt_buf[COMMENT_BUFFER_SIZE];

    for (int i = start_offset; i < max_check && consecutive_invalid < CONSECUTIVE_INVALID_THRESHOLD; ++i) {
        ea_t entry_addr = vtable_addr + (i * ptr_size);
        if (!is_mapped(entry_addr)) break;

        if (std::binary_search(sorted_vtables.begin(), sorted_vtables.end(), entry_addr) &&
            entry_addr != vtable_addr) break;

        ea_t func_ptr = read_ptr(entry_addr);
        if (!func_ptr || func_ptr == BADADDR) {
            ++consecutive_invalid;
            continue;
        }

        bool pure_virt = is_pure_virtual(func_ptr);

        if (!pure_virt && !is_valid_func_ptr(func_ptr)) {
            if (is_typeinfo(func_ptr)) {
                ++consecutive_invalid;
                continue;
            }
            ++consecutive_invalid;
            continue;
        }

        consecutive_invalid = 0;
        stats.func_count++;
        if (pure_virt) stats.pure_virtual_count++;

        if constexpr (collect_entries) {
            if (out_entries) {
                out_entries->push_back({entry_addr, func_ptr, vfunc_index, pure_virt});
            }
        }

        if constexpr (annotate) {
            if (!is_code(get_flags(func_ptr)))
                add_func(func_ptr);

            int byte_offset = vfunc_index * ptr_size;
            qsnprintf(cmt_buf, sizeof(cmt_buf), "index: %d | offset: %d", vfunc_index, byte_offset);
            set_cmt(entry_addr, cmt_buf, false);
        }

        ++vfunc_index;
    }

    return stats;
}

inline VTableStats get_vtable_stats(ea_t addr, bool is_win, const std::vector<ea_t>& vtables) {
    return scan_vtable<false, false>(addr, is_win, vtables);
}

inline std::vector<VTableEntry> get_vtable_entries(ea_t addr, bool is_win, const std::vector<ea_t>& vtables) {
    using namespace vtable_utils;

    std::vector<VTableEntry> entries;
    entries.reserve(ENTRY_RESERVE_SIZE);
    scan_vtable<true, false>(addr, is_win, vtables, &entries);
    return entries;
}

inline int annotate_vtable(ea_t addr, bool is_win, const std::vector<ea_t>& vtables) {
    return scan_vtable<false, true>(addr, is_win, vtables).func_count;
}

} // namespace smart_annotator
