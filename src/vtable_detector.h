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

struct VTableInfo {
    ea_t address;
    std::string class_name;
    std::string display_name;
    bool is_windows;
};

namespace vtable_detector {

// Check if extracted class name is valid
inline bool is_valid_class_name(const std::string& name) {
    // Minimum 3 characters, maximum 100 characters
    if (name.empty() || name.length() < 3 || name.length() > 100)
        return false;

    // Must start with uppercase letter or underscore (C++ class naming convention)
    char first = name[0];
    if (!isupper(first) && first != '_')
        return false;

    // Filter out names that are just special characters
    bool has_alnum = false;
    for (char c : name) {
        if (isalnum(c) || c == '_') {
            has_alnum = true;
            break;
        }
    }

    if (!has_alnum)
        return false;

    // Filter out names that are just repeated single characters (like "EE", "EEE", "___")
    bool all_same = true;
    char first_char = name[0];
    for (size_t i = 1; i < name.length(); ++i) {
        if (name[i] != first_char) {
            all_same = false;
            break;
        }
    }

    if (all_same)
        return false;

    // Check ratio of alphanumeric to total length (should be mostly alphanumeric)
    int alnum_count = 0;
    for (char c : name) {
        if (isalnum(c) || c == '_')
            alnum_count++;
    }

    // At least 60% should be alphanumeric/underscore
    if ((float)alnum_count / name.length() < 0.6f)
        return false;

    // Filter out names with excessive Itanium mangling artifacts
    // Only reject if there are MANY mangling patterns (likely broken extraction)
    int mangling_pattern_count = 0;
    for (size_t i = 0; i < name.length() - 1; ++i) {
        // Count EL, EE, L<digit> patterns
        if ((name[i] == 'E' && (name[i+1] == 'L' || name[i+1] == 'E')) ||
            (name[i] == 'L' && isdigit(name[i+1]))) {
            mangling_pattern_count++;
        }
    }
    // Only reject if more than 3 mangling patterns (very likely broken)
    if (mangling_pattern_count > 3)
        return false;

    return true;
}

// Demangle and extract class name from symbol
inline std::string extract_class_name(const char* mangled_name, bool& is_windows) {
    std::string sym_name(mangled_name);
    qstring demangled;
    is_windows = false;

    if (sym_name.length() > 4 && sym_name.substr(sym_name.length() - 4) == "_ptr")
        sym_name = sym_name.substr(0, sym_name.length() - 4);

    int demangle_result = demangle_name(&demangled, sym_name.c_str(), MNG_NODEFINIT);

    if (demangle_result > 0) {
        std::string dem_str(demangled.c_str());

        if (dem_str.find("vtable for") != std::string::npos) {
            size_t pos = dem_str.find("vtable for ");
            if (pos != std::string::npos) {
                std::string class_name = dem_str.substr(pos + 11);
                if (is_valid_class_name(class_name))
                    return class_name;
            }
        }

        if (dem_str.find("vftable") != std::string::npos) {
            is_windows = true;
            size_t const_pos = dem_str.find("const ");
            size_t vft_pos = dem_str.find("::`vftable'");

            if (const_pos != std::string::npos && vft_pos != std::string::npos) {
                size_t start = const_pos + 6;
                std::string class_name = dem_str.substr(start, vft_pos - start);
                if (is_valid_class_name(class_name))
                    return class_name;
            }
        }
    }

    // Fallback: parse Itanium mangling manually
    if (sym_name.rfind("_ZTV", 0) == 0) {
        const char* name_start = sym_name.c_str() + 4;

        if (name_start[0] == 'N') {
            const char* p = name_start + 1;
            std::string last_component;

            while (*p && *p != 'E') {
                if (isdigit(*p)) {
                    int len = atoi(p);
                    while (isdigit(*p)) p++;

                    if (len > 0 && len < 1024) {
                        last_component = std::string(p, len);
                        p += len;
                    }
                } else {
                    p++;
                }
            }

            if (is_valid_class_name(last_component))
                return last_component;
        }
        else if (isdigit(name_start[0])) {
            int name_len = atoi(name_start);
            const char* name_ptr = name_start;
            while (isdigit(*name_ptr)) name_ptr++;

            if (name_len > 0 && name_len < 1024) {
                std::string class_name(name_ptr, name_len);

                // Try to clean up mangling artifacts from the extracted name
                // Look for patterns like "E18CSVCMsg_HLTVStatusL13..." and extract "CSVCMsg_HLTVStatus"
                if (!is_valid_class_name(class_name)) {
                    // Find the first uppercase letter after any leading digits/chars
                    size_t first_upper = 0;
                    for (size_t i = 0; i < class_name.length(); ++i) {
                        if (isupper(class_name[i])) {
                            first_upper = i;
                            break;
                        }
                    }

                    // Find where template encoding starts (L<digit> pattern)
                    size_t template_start = class_name.find_first_of('L');
                    while (template_start != std::string::npos) {
                        if (template_start + 1 < class_name.length() && isdigit(class_name[template_start + 1])) {
                            break;  // Found L<digit>
                        }
                        template_start = class_name.find_first_of('L', template_start + 1);
                    }

                    if (first_upper < class_name.length()) {
                        size_t end_pos = (template_start != std::string::npos) ? template_start : class_name.length();
                        std::string cleaned = class_name.substr(first_upper, end_pos - first_upper);

                        if (is_valid_class_name(cleaned))
                            return cleaned;
                    }
                }

                if (is_valid_class_name(class_name))
                    return class_name;
            }
        }
    }

    return "";
}

// Symbol-based vtable detection (like Python version)
inline std::vector<VTableInfo> find_vtables() {
    std::vector<VTableInfo> vtables;
    std::map<std::string, ea_t> seen;

    size_t name_count = get_nlist_size();

    for (size_t i = 0; i < name_count; ++i) {
        ea_t ea = get_nlist_ea(i);
        const char* name = get_nlist_name(i);

        if (!name || name[0] == '\0')
            continue;

        std::string sym_name(name);
        bool is_windows = false;
        std::string class_name;

        // Linux/GCC vtables: _ZTV prefix
        if (sym_name.rfind("_ZTV", 0) == 0) {
            class_name = extract_class_name(sym_name.c_str(), is_windows);

            if (is_valid_class_name(class_name)) {
                VTableInfo info;
                info.address = ea;
                info.class_name = class_name;
                info.display_name = class_name + " (Linux/GCC)";
                info.is_windows = false;

                if (seen.find(info.display_name) == seen.end()) {
                    seen[info.display_name] = ea;
                    vtables.push_back(info);
                }
            }
        }
        // Windows/MSVC vtables: ??_7 prefix
        else if (sym_name.rfind("??_7", 0) == 0) {
            class_name = extract_class_name(sym_name.c_str(), is_windows);

            if (class_name.empty() && sym_name.find("@@6B@") != std::string::npos) {
                class_name = sym_name.substr(4, sym_name.find("@@6B@") - 4);
            }

            if (is_valid_class_name(class_name)) {
                VTableInfo info;
                info.address = ea;
                info.class_name = class_name;
                info.display_name = class_name + " (Windows/MSVC)";
                info.is_windows = true;

                if (seen.find(info.display_name) == seen.end()) {
                    seen[info.display_name] = ea;
                    vtables.push_back(info);
                }
            }
        }
        // Additional patterns: vftable, vtbl in name
        else if (sym_name.find("vftable") != std::string::npos ||
                 sym_name.find("vtbl") != std::string::npos) {

            class_name = extract_class_name(sym_name.c_str(), is_windows);

            if (class_name.empty()) {
                class_name = sym_name;
                is_windows = true;
            }

            if (is_valid_class_name(class_name)) {
                VTableInfo info;
                info.address = ea;
                info.class_name = class_name;
                info.display_name = class_name + " (Detected)";
                info.is_windows = is_windows;

                if (seen.find(info.display_name) == seen.end()) {
                    seen[info.display_name] = ea;
                    vtables.push_back(info);
                }
            }
        }
    }

    // Sort by class name
    std::sort(vtables.begin(), vtables.end(),
        [](const VTableInfo& a, const VTableInfo& b) {
            return a.display_name < b.display_name;
        });

    return vtables;
}

} // namespace vtable_detector
