#pragma once
#include <string>
#include <vector>
#include <ida.hpp>
#include "vtable_detector.h"
#include "smart_annotator.h"
#include "vtable_comparison.h"
#include "vtable_utils.h"

namespace vtable_json {

// Minimal JSON helpers — no external dependencies

inline std::string escape_json(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

inline std::string addr_str(ea_t addr) {
    if (addr == BADADDR) return "null";
    char buf[32];
    qsnprintf(buf, sizeof(buf), "\"0x%llX\"", (unsigned long long)addr);
    return buf;
}

inline std::string json_str(const std::string &s) {
    return "\"" + escape_json(s) + "\"";
}

inline std::string json_bool(bool v) {
    return v ? "true" : "false";
}

inline std::string json_int(int v) {
    char buf[16];
    qsnprintf(buf, sizeof(buf), "%d", v);
    return buf;
}

inline std::string string_array(const std::vector<std::string> &arr) {
    std::string out = "[";
    for (size_t i = 0; i < arr.size(); ++i) {
        if (i > 0) out += ",";
        out += json_str(arr[i]);
    }
    out += "]";
    return out;
}

// --- Serialization functions ---

inline std::string vtables_to_json(const std::vector<VTableInfo> &vtables) {
    std::string out = "[";
    bool first = true;
    for (const auto &vt : vtables) {
        if (!first) out += ",";
        first = false;
        out += "{";
        out += "\"address\":" + addr_str(vt.address);
        out += ",\"class_name\":" + json_str(vt.class_name);
        out += ",\"display_name\":" + json_str(vt.display_name);
        out += ",\"func_count\":" + json_int(vt.func_count);
        out += ",\"pure_virtual_count\":" + json_int(vt.pure_virtual_count);
        out += ",\"is_abstract\":" + json_bool(vt.pure_virtual_count > 0);
        out += ",\"base_classes\":" + string_array(vt.base_classes);
        out += ",\"derived_classes\":" + string_array(vt.derived_classes);
        out += ",\"derived_count\":" + json_int(vt.derived_count);
        out += ",\"has_multiple_inheritance\":" + json_bool(vt.has_multiple_inheritance);
        out += ",\"has_virtual_inheritance\":" + json_bool(vt.has_virtual_inheritance);
        out += ",\"is_intermediate\":" + json_bool(vt.is_intermediate);
        out += ",\"is_windows\":" + json_bool(vt.is_windows);
        out += "}";
    }
    out += "]";
    return out;
}

inline std::string vtable_entries_to_json(
    ea_t vtable_addr,
    const std::string &class_name,
    const std::vector<smart_annotator::VTableEntry> &entries)
{
    std::string out = "{";
    out += "\"address\":" + addr_str(vtable_addr);
    out += ",\"class_name\":" + json_str(class_name);
    out += ",\"entries\":[";
    bool first = true;
    for (const auto &e : entries) {
        if (!first) out += ",";
        first = false;

        // Get function name
        qstring name;
        std::string func_name;
        if (get_name(&name, e.func_ptr) && name.length() > 0)
            func_name = std::string(name.c_str());

        out += "{";
        out += "\"index\":" + json_int(e.index);
        out += ",\"slot_addr\":" + addr_str(e.entry_addr);
        out += ",\"func_addr\":" + addr_str(e.func_ptr);
        out += ",\"func_name\":" + json_str(func_name);
        out += ",\"is_pure_virtual\":" + json_bool(e.is_pure_virtual);
        out += "}";
    }
    out += "]}";
    return out;
}

inline const char *override_status_str(vtable_comparison::OverrideStatus s) {
    switch (s) {
        case vtable_comparison::OverrideStatus::INHERITED:    return "inherited";
        case vtable_comparison::OverrideStatus::OVERRIDDEN:   return "overridden";
        case vtable_comparison::OverrideStatus::NEW_VIRTUAL:  return "new_virtual";
        case vtable_comparison::OverrideStatus::PURE_TO_IMPL: return "pure_to_impl";
        case vtable_comparison::OverrideStatus::IMPL_TO_PURE: return "impl_to_pure";
        default: return "unknown";
    }
}

inline std::string vtable_comparison_to_json(
    const vtable_comparison::VTableComparison &cmp)
{
    std::string out = "{";
    out += "\"derived_class\":" + json_str(cmp.derived_class);
    out += ",\"base_class\":" + json_str(cmp.base_class);
    out += ",\"derived_vtable\":" + addr_str(cmp.derived_vtable);
    out += ",\"base_vtable\":" + addr_str(cmp.base_vtable);
    out += ",\"inherited_count\":" + json_int(cmp.inherited_count);
    out += ",\"overridden_count\":" + json_int(cmp.overridden_count);
    out += ",\"new_virtual_count\":" + json_int(cmp.new_virtual_count);
    out += ",\"entries\":[";
    bool first = true;
    for (const auto &e : cmp.entries) {
        if (!first) out += ",";
        first = false;
        out += "{";
        out += "\"index\":" + json_int(e.index);
        out += ",\"derived_func_addr\":" + addr_str(e.derived_func_ptr);
        out += ",\"derived_func_name\":" + json_str(e.derived_func_name);
        out += ",\"base_func_addr\":" + addr_str(e.base_func_ptr);
        out += ",\"base_func_name\":" + json_str(e.base_func_name);
        out += ",\"status\":\"" + std::string(override_status_str(e.status)) + "\"";
        out += ",\"is_pure_virtual_base\":" + json_bool(e.is_pure_virtual_base);
        out += ",\"is_pure_virtual_derived\":" + json_bool(e.is_pure_virtual_derived);
        out += "}";
    }
    out += "]}";
    return out;
}

inline std::string vtable_hierarchy_to_json(
    const std::string &root_class,
    const std::vector<VTableInfo> &vtables)
{
    // Find the root vtable
    const VTableInfo *root = nullptr;
    for (const auto &vt : vtables) {
        if (vt.class_name == root_class) {
            root = &vt;
            break;
        }
    }

    if (!root)
        return "{\"error\":\"class not found\",\"class_name\":" + json_str(root_class) + "}";

    // Build class->vtable map
    std::map<std::string, const VTableInfo *> vtable_map;
    for (const auto &vt : vtables)
        vtable_map[vt.class_name] = &vt;

    // Collect ancestors
    std::vector<std::string> ancestors;
    {
        std::set<std::string> seen;
        std::function<void(const std::string &)> walk_up;
        walk_up = [&](const std::string &cls) {
            auto it = vtable_map.find(cls);
            if (it == vtable_map.end()) return;
            for (const auto &base : it->second->base_classes) {
                if (seen.insert(base).second) {
                    ancestors.push_back(base);
                    walk_up(base);
                }
            }
        };
        walk_up(root_class);
    }

    // Collect descendants
    std::vector<std::string> descendants;
    {
        std::set<std::string> seen;
        std::function<void(const std::string &)> walk_down;
        walk_down = [&](const std::string &cls) {
            for (const auto &vt : vtables) {
                for (const auto &base : vt.base_classes) {
                    if (base == cls && seen.insert(vt.class_name).second) {
                        descendants.push_back(vt.class_name);
                        walk_down(vt.class_name);
                        break;
                    }
                }
            }
        };
        walk_down(root_class);
    }

    std::string out = "{";
    out += "\"class_name\":" + json_str(root->class_name);
    out += ",\"address\":" + addr_str(root->address);
    out += ",\"func_count\":" + json_int(root->func_count);
    out += ",\"is_abstract\":" + json_bool(root->pure_virtual_count > 0);
    out += ",\"ancestors\":" + string_array(ancestors);
    out += ",\"descendants\":" + string_array(descendants);
    out += ",\"base_classes\":" + string_array(root->base_classes);
    out += ",\"derived_classes\":" + string_array(root->derived_classes);
    out += "}";
    return out;
}

} // namespace vtable_json
