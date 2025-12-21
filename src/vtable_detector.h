#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include "vtable_utils.h"

struct VTableInfo {
    ea_t address;
    std::string class_name;
    std::string display_name;
    bool is_windows;
    int func_count;
    int pure_virtual_count;
    std::vector<std::string> base_classes;
    std::vector<std::string> derived_classes;
    int derived_count;
    bool has_multiple_inheritance;
    bool has_virtual_inheritance;
    bool is_intermediate;        // True if class has no vtable but exists in RTTI chain
    ea_t parent_vtable_addr;     // For intermediate: parent's vtable address
    std::string parent_class;    // Direct parent class name
};

namespace vtable_detector {

using vtable_utils::normalize_msvc_nested_class;

inline bool is_valid_class_name(const std::string& name) {
    using namespace vtable_utils;

    const size_t len = name.length();
    if (len < MIN_CLASS_NAME_LENGTH || len > MAX_CLASS_NAME_LENGTH) return false;

    const char first = name[0];
    if (!isupper(first) && first != '_') return false;

    int alnum_count = 0;
    bool all_same = true;

    for (size_t i = 0; i < len; ++i) {
        const char c = name[i];
        if (isalnum(c) || c == '_') ++alnum_count;
        if (i > 0 && c != first) all_same = false;
    }

    return alnum_count > 0 && !all_same;
}

inline std::string extract_class_name(const char* mangled_name, bool& is_windows) {
    using namespace vtable_utils;

    std::string sym_name(mangled_name);
    is_windows = false;

    if (sym_name.length() > 4 && sym_name.compare(sym_name.length() - 4, 4, "_ptr") == 0)
        sym_name.resize(sym_name.length() - 4);

    qstring demangled;
    if (demangle_name(&demangled, sym_name.c_str(), MNG_NODEFINIT) > 0) {
        const char* dem = demangled.c_str();

        const char* vtable_pos = strstr(dem, "vtable for ");
        if (vtable_pos) {
            std::string class_name(vtable_pos + 11);
            class_name = normalize_msvc_nested_class(class_name);
            if (is_valid_class_name(class_name)) return class_name;
        }

        const char* vft_pos = strstr(dem, "::`vftable'");
        if (vft_pos) {
            is_windows = true;
            const char* const_pos = strstr(dem, "const ");
            if (const_pos && const_pos < vft_pos) {
                std::string class_name(const_pos + 6, vft_pos - const_pos - 6);
                class_name = normalize_msvc_nested_class(class_name);  // @ -> ::
                if (is_valid_class_name(class_name)) return class_name;
            }
        }
    }

    if (sym_name.compare(0, 4, "_ZTV") != 0) return "";

    const char* p = sym_name.c_str() + 4;
    const char* end = sym_name.c_str() + sym_name.length();

    if (*p == 'N') {
        std::string last_component;
        for (++p; *p && *p != 'E'; ) {
            if (!isdigit(*p)) { ++p; continue; }

            int len = atoi(p);
            while (isdigit(*p)) ++p;
            if (len <= 0 || len >= (int)MAX_COMPONENT_LENGTH || p + len > end) break;

            last_component.assign(p, len);
            p += len;
        }
        last_component = normalize_msvc_nested_class(last_component);
        if (is_valid_class_name(last_component)) return last_component;
    }
    else if (isdigit(*p)) {
        int len = atoi(p);
        while (isdigit(*p)) ++p;
        if (len <= 0 || len >= (int)MAX_COMPONENT_LENGTH || p + len > end) return "";

        std::string class_name(p, len);
        class_name = normalize_msvc_nested_class(class_name);
        if (is_valid_class_name(class_name)) return class_name;

        size_t first_upper = class_name.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (first_upper != std::string::npos) {
            size_t template_start = std::string::npos;
            for (size_t i = first_upper; i + 1 < class_name.length(); ++i) {
                if (class_name[i] == 'L' && isdigit(class_name[i + 1])) {
                    template_start = i;
                    break;
                }
            }
            size_t end_pos = (template_start != std::string::npos) ? template_start : class_name.length();
            std::string cleaned = class_name.substr(first_upper, end_pos - first_upper);
            cleaned = normalize_msvc_nested_class(cleaned);
            if (is_valid_class_name(cleaned)) return cleaned;
        }
    }

    return "";
}

inline std::vector<VTableInfo> find_vtables() {
    using namespace vtable_utils;

    std::vector<VTableInfo> vtables;
    std::map<std::string, ea_t> seen;

    const size_t name_count = get_nlist_size();
    vtables.reserve(name_count / VTABLE_RESERVE_RATIO);

    auto add_vtable = [&](ea_t ea, const std::string& class_name, bool is_win) {
        if (seen.emplace(class_name, ea).second) {
            VTableInfo vt;
            vt.address = ea;
            vt.class_name = class_name;
            vt.display_name = class_name;
            vt.is_windows = is_win;
            vt.func_count = 0;
            vt.pure_virtual_count = 0;
            vt.derived_count = 0;
            vt.has_multiple_inheritance = false;
            vt.has_virtual_inheritance = false;
            vt.is_intermediate = false;
            vt.parent_vtable_addr = BADADDR;
            vtables.push_back(std::move(vt));
        }
    };

    for (size_t i = 0; i < name_count; ++i) {
        const char* name = get_nlist_name(i);
        if (!name || !*name) continue;

        ea_t ea = get_nlist_ea(i);
        bool is_windows = false;
        std::string class_name;

        if (strncmp(name, "_ZTV", 4) == 0) {
            class_name = extract_class_name(name, is_windows);
            if (is_valid_class_name(class_name))
                add_vtable(ea, class_name, false);
        }
        else if (strncmp(name, "??_7", 4) == 0) {
            class_name = extract_class_name(name, is_windows);
            if (class_name.empty()) {
                const char* marker = strstr(name, "@@6B@");
                if (marker) {
                    class_name.assign(name + 4, marker - name - 4);
                    class_name = normalize_msvc_nested_class(class_name);
                }
            }
            if (is_valid_class_name(class_name))
                add_vtable(ea, class_name, true);
        }
        else if (strstr(name, "vftable") || strstr(name, "vtbl")) {
            class_name = extract_class_name(name, is_windows);
            if (class_name.empty()) {
                class_name = name;
                is_windows = true;
                class_name = normalize_msvc_nested_class(class_name);
            }
            if (is_valid_class_name(class_name))
                add_vtable(ea, class_name, is_windows);
        }
    }

    std::sort(vtables.begin(), vtables.end(),
        [](const VTableInfo& a, const VTableInfo& b) { return a.class_name < b.class_name; });

    return vtables;
}

} // namespace vtable_detector
