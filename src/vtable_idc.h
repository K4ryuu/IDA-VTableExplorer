#pragma once
#include <ida.hpp>
#include <expr.hpp>
#include "vtable_chooser.h"
#include "vtable_json.h"

// IDC functions exposing VTableExplorer data as JSON strings.
// Call from IDAPython: idc.eval_idc('VTableExplorer_Scan()')

namespace vtable_idc {

// Ensure the global cache is populated
static void ensure_cache() {
    if (!g_vtable_cache.valid)
        g_vtable_cache.refresh();
}

// --- IDC function implementations ---

static error_t idaapi idc_scan(idc_value_t * /*argv*/, idc_value_t *res) {
    ensure_cache();
    std::string json = vtable_json::vtables_to_json(g_vtable_cache.vtables);
    res->_set_string(qstring(json.c_str()));
    return eOk;
}

static error_t idaapi idc_entries(idc_value_t *argv, idc_value_t *res) {
    ensure_cache();
    ea_t addr = (ea_t)argv[0].num;

    // Find the vtable info
    const VTableInfo *vt = nullptr;
    for (const auto &v : g_vtable_cache.vtables) {
        if (v.address == addr) { vt = &v; break; }
    }
    if (!vt) {
        res->_set_string(qstring("{\"error\":\"vtable not found\"}"));
        return eOk;
    }

    ea_t browse_addr = vt->is_intermediate ? vt->parent_vtable_addr : vt->address;
    if (browse_addr == BADADDR) {
        res->_set_string(qstring("{\"error\":\"no vtable address\"}"));
        return eOk;
    }

    auto entries = smart_annotator::get_vtable_entries(
        browse_addr, vt->is_windows, g_vtable_cache.sorted_addrs);
    std::string json = vtable_json::vtable_entries_to_json(
        browse_addr, vt->class_name, entries);
    res->_set_string(qstring(json.c_str()));
    return eOk;
}

static error_t idaapi idc_compare(idc_value_t *argv, idc_value_t *res) {
    ensure_cache();
    ea_t derived_addr = (ea_t)argv[0].num;
    ea_t base_addr    = (ea_t)argv[1].num;

    // Resolve class names
    std::string derived_name, base_name;
    bool is_windows = false;
    for (const auto &v : g_vtable_cache.vtables) {
        if (v.address == derived_addr) { derived_name = v.class_name; is_windows = v.is_windows; }
        if (v.address == base_addr)    { base_name = v.class_name; }
    }

    auto cmp = vtable_comparison::compare_vtables(
        derived_addr, base_addr, is_windows,
        g_vtable_cache.sorted_addrs, derived_name, base_name);
    std::string json = vtable_json::vtable_comparison_to_json(cmp);
    res->_set_string(qstring(json.c_str()));
    return eOk;
}

static error_t idaapi idc_hierarchy(idc_value_t *argv, idc_value_t *res) {
    ensure_cache();
    std::string class_name(argv[0].c_str());
    std::string json = vtable_json::vtable_hierarchy_to_json(
        class_name, g_vtable_cache.vtables);
    res->_set_string(qstring(json.c_str()));
    return eOk;
}

// --- Registration ---

static const char idc_scan_args[]      = { 0 };
static const char idc_entries_args[]   = { VT_LONG, 0 };
static const char idc_compare_args[]   = { VT_LONG, VT_LONG, 0 };
static const char idc_hierarchy_args[] = { VT_STR, 0 };

static const ext_idcfunc_t idc_funcs[] = {
    { "VTableExplorer_Scan",      idc_scan,      idc_scan_args,      nullptr, 0, EXTFUN_BASE },
    { "VTableExplorer_Entries",   idc_entries,   idc_entries_args,   nullptr, 0, EXTFUN_BASE },
    { "VTableExplorer_Compare",   idc_compare,   idc_compare_args,   nullptr, 0, EXTFUN_BASE },
    { "VTableExplorer_Hierarchy", idc_hierarchy, idc_hierarchy_args, nullptr, 0, EXTFUN_BASE },
};

inline void register_vtable_idc_functions() {
    for (const auto &f : idc_funcs)
        add_idc_func(f);
}

inline void unregister_vtable_idc_functions() {
    for (const auto &f : idc_funcs)
        del_idc_func(f.name);
}

} // namespace vtable_idc
