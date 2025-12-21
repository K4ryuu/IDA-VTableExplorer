#pragma once
#include <ida.hpp>
#include <vector>
#include <string>
#include <map>
#include "rtti_parser.h"
#include "smart_annotator.h"
#include "vtable_utils.h"

namespace vtable_comparison {

enum class OverrideStatus {
    INHERITED,
    OVERRIDDEN,
    NEW_VIRTUAL,
    PURE_TO_IMPL,
    IMPL_TO_PURE
};

struct ComparisonEntry {
    int index;
    ea_t derived_entry_addr;
    ea_t derived_func_ptr;
    ea_t base_entry_addr;
    ea_t base_func_ptr;
    OverrideStatus status;
    bool is_pure_virtual_base;
    bool is_pure_virtual_derived;
    std::string base_func_name;
    std::string derived_func_name;
};

struct VTableComparison {
    std::string derived_class;
    std::string base_class;
    ea_t derived_vtable;
    ea_t base_vtable;
    std::vector<ComparisonEntry> entries;
    int inherited_count;
    int overridden_count;
    int new_virtual_count;
};

inline std::string get_func_name(ea_t func) {
    if (!func || func == BADADDR) return "";
    qstring name;
    return get_name(&name, func) ? std::string(name.c_str()) : "";
}

inline VTableComparison compare_vtables(
    ea_t derived_vt, ea_t base_vt, bool is_win,
    const std::vector<ea_t>& sorted,
    const std::string& derived_cls = "",
    const std::string& base_cls = "")
{
    VTableComparison r;
    r.derived_class = derived_cls;
    r.base_class = base_cls;
    r.derived_vtable = derived_vt;
    r.base_vtable = base_vt;
    r.inherited_count = r.overridden_count = r.new_virtual_count = 0;

    auto derived_entries = smart_annotator::get_vtable_entries(derived_vt, is_win, sorted);
    auto base_entries = smart_annotator::get_vtable_entries(base_vt, is_win, sorted);

    std::map<int, smart_annotator::VTableEntry> base_map;
    for (const auto& e : base_entries) base_map[e.index] = e;

    for (const auto& d : derived_entries) {
        ComparisonEntry c;
        c.index = d.index;
        c.derived_entry_addr = d.entry_addr;
        c.derived_func_ptr = d.func_ptr;
        c.is_pure_virtual_derived = d.is_pure_virtual;
        c.derived_func_name = get_func_name(d.func_ptr);

        auto it = base_map.find(d.index);
        if (it != base_map.end()) {
            const auto& b = it->second;
            c.base_entry_addr = b.entry_addr;
            c.base_func_ptr = b.func_ptr;
            c.is_pure_virtual_base = b.is_pure_virtual;
            c.base_func_name = get_func_name(b.func_ptr);

            if (c.derived_func_ptr == c.base_func_ptr) {
                c.status = OverrideStatus::INHERITED;
                r.inherited_count++;
            } else {
                if (c.is_pure_virtual_base && !c.is_pure_virtual_derived)
                    c.status = OverrideStatus::PURE_TO_IMPL;
                else if (!c.is_pure_virtual_base && c.is_pure_virtual_derived)
                    c.status = OverrideStatus::IMPL_TO_PURE;
                else
                    c.status = OverrideStatus::OVERRIDDEN;
                r.overridden_count++;
            }
        } else {
            c.base_entry_addr = BADADDR;
            c.base_func_ptr = BADADDR;
            c.is_pure_virtual_base = false;
            c.status = OverrideStatus::NEW_VIRTUAL;
            r.new_virtual_count++;
        }
        r.entries.push_back(c);
    }
    return r;
}

inline ea_t find_vtable_by_class_name(const std::string& name, const std::vector<VTableInfo>& vtables) {
    for (const auto& vt : vtables)
        if (vt.class_name == name) return vt.address;
    return BADADDR;
}

inline const char* get_status_string(OverrideStatus s) {
    switch (s) {
        case OverrideStatus::INHERITED:    return "Inherited";
        case OverrideStatus::OVERRIDDEN:   return "Overridden";
        case OverrideStatus::NEW_VIRTUAL:  return "New Virtual";
        case OverrideStatus::PURE_TO_IMPL: return "Pure→Impl";
        case OverrideStatus::IMPL_TO_PURE: return "Impl→Pure";
        default: return "Unknown";
    }
}

inline uint32 get_status_color(OverrideStatus s) {
    using namespace vtable_utils;
    switch (s) {
        case OverrideStatus::INHERITED:    return STATUS_INHERITED;
        case OverrideStatus::OVERRIDDEN:   return STATUS_OVERRIDDEN;
        case OverrideStatus::NEW_VIRTUAL:  return STATUS_NEW_VIRTUAL;
        case OverrideStatus::PURE_TO_IMPL: return STATUS_PURE_TO_IMPL;
        case OverrideStatus::IMPL_TO_PURE: return STATUS_IMPL_TO_PURE;
        default: return DEFAULT_BG;
    }
}

} // namespace vtable_comparison
