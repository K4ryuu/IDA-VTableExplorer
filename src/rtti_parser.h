#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <segment.hpp>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include "vtable_utils.h"
#include "rtti_detector.h"

namespace rtti_parser {

using vtable_utils::get_ptr_size;
using vtable_utils::read_ptr;
using vtable_utils::read_int32;

struct BaseClassInfo {
    std::string class_name;
    ea_t vtable_addr = BADADDR;
    int offset = 0;
    bool is_virtual = false;
};

struct InheritanceInfo {
    std::string class_name;
    std::vector<BaseClassInfo> base_classes;
    bool has_multiple_inheritance = false;
    bool has_virtual_inheritance = false;
};

namespace gcc_rtti {

inline std::string read_string(ea_t addr) {
    if (!is_mapped(addr)) return "";
    std::string r;
    r.reserve(128);
    for (int i = 0; i < vtable_utils::MAX_RTTI_STRING_LENGTH; ++i) {
        char c = get_byte(addr + i);
        if (!c || (!isprint(c) && c != '_')) break;
        r.push_back(c);
    }
    return r;
}

inline std::string extract_class_from_mangled(const std::string& m) {
    if (m.empty()) return "";

    // _ZTS prefix
    if (m.compare(0, 4, "_ZTS") == 0 && m.length() > 4) {
        const char* p = m.c_str() + 4;
        if (isdigit(*p)) {
            int len = atoi(p);
            while (isdigit(*p)) ++p;
            if (len > 0 && len < 256 && strlen(p) >= (size_t)len)
                return std::string(p, len);
        }
    }

    // Nested name (N...E)
    if (m[0] == 'N') {
        std::string r;
        const char* p = m.c_str() + 1;
        while (*p && *p != 'E') {
            if (!isdigit(*p)) break;
            int len = atoi(p);
            while (isdigit(*p)) ++p;
            if (len <= 0 || len >= 256 || strlen(p) < (size_t)len) break;
            if (!r.empty()) r += "::";
            r.append(p, len);
            p += len;
        }
        if (!r.empty()) return r;
    }
    // Simple name
    else if (isdigit(m[0])) {
        const char* p = m.c_str();
        int len = atoi(p);
        while (isdigit(*p)) ++p;
        if (len > 0 && len < 256 && strlen(p) >= (size_t)len)
            return std::string(p, len);
    }

    // Fallback: demangle
    qstring dem;
    if (demangle_name(&dem, m.c_str(), MNG_NODEFINIT) > 0) {
        std::string s = dem.c_str();
        size_t pos = s.find("typeinfo for ");
        return (pos != std::string::npos) ? s.substr(pos + 13) : s;
    }
    return "";
}

inline InheritanceInfo parse_gcc_typeinfo(ea_t ti_addr, const std::string& derived) {
    InheritanceInfo info;
    info.class_name = derived;
    if (!is_mapped(ti_addr)) return info;

    const int ps = get_ptr_size();
    ea_t vt = read_ptr(ti_addr);
    ea_t name = read_ptr(ti_addr + ps);

    if (vt == BADADDR || name == BADADDR) return info;

    qstring vt_name;
    bool got = get_name(&vt_name, vt) && vt_name.find("off_") != 0;

    if (!got) {
        ea_t indirect = read_ptr(vt);
        if (indirect != BADADDR && is_mapped(indirect))
            got = get_name(&vt_name, indirect);

        if (!got) {
            // Try to get base from structure
            ea_t base_ti = read_ptr(ti_addr + 2 * ps);
            if (base_ti != BADADDR && is_mapped(base_ti)) {
                ea_t bn = read_ptr(base_ti + ps);
                if (bn != BADADDR) {
                    std::string bc = extract_class_from_mangled(read_string(bn));
                    if (!bc.empty()) {
                        BaseClassInfo b;
                        b.class_name = bc;
                        info.base_classes.push_back(b);
                    }
                }
            }
            return info;
        }
    }

    const char* n = vt_name.c_str();

    // Single inheritance
    if (strstr(n, "__si_class_type_info")) {
        ea_t base_ti = read_ptr(ti_addr + 2 * ps);
        if (base_ti != BADADDR) {
            ea_t bn = read_ptr(base_ti + ps);
            if (bn != BADADDR) {
                std::string bc = extract_class_from_mangled(read_string(bn));
                if (!bc.empty()) {
                    BaseClassInfo b;
                    b.class_name = bc;
                    info.base_classes.push_back(b);
                }
            }
        }
    }
    // Multiple/virtual inheritance
    else if (strstr(n, "__vmi_class_type_info")) {
        info.has_multiple_inheritance = true;
        int32 flags = read_int32(ti_addr + 2 * ps);
        int32 cnt = read_int32(ti_addr + 3 * ps);
        if (flags & 1) info.has_virtual_inheritance = true;

        if (cnt > 0 && cnt < 32) {
            ea_t arr = ti_addr + 4 * ps;
            for (int32 i = 0; i < cnt; ++i) {
                ea_t entry = arr + (i * 2 * ps);
                ea_t base_ti = read_ptr(entry);
                int32 off_flags = read_int32(entry + ps);
                if (base_ti != BADADDR) {
                    ea_t bn = read_ptr(base_ti + ps);
                    if (bn != BADADDR) {
                        std::string bc = extract_class_from_mangled(read_string(bn));
                        if (!bc.empty()) {
                            BaseClassInfo b;
                            b.class_name = bc;
                            b.offset = off_flags >> 8;
                            b.is_virtual = (off_flags & 1) != 0;
                            info.base_classes.push_back(b);
                        }
                    }
                }
            }
        }
    }
    return info;
}

} // namespace gcc_rtti

namespace msvc_rtti {

using vtable_utils::normalize_msvc_nested_class;
using vtable_utils::clean_msvc_decorated_name;

inline ea_t rva_to_va(ea_t base, int32 rva) {
    return rva ? base + rva : BADADDR;
}

inline std::string read_msvc_type_name(ea_t td) {
    if (!is_mapped(td)) return "";

    const int ps = get_ptr_size();
    ea_t name_addr = td + 2 * ps;

    std::string raw;
    raw.reserve(128);
    for (int i = 0; i < vtable_utils::MAX_RTTI_STRING_LENGTH; ++i) {
        char c = get_byte(name_addr + i);
        if (!c || (!isprint(c) && c != '_')) break;
        raw.push_back(c);
    }

    const char* to_dem = raw.c_str();
    if (!raw.empty() && raw[0] == '.') to_dem++;

    qstring dem;
    if (demangle_name(&dem, to_dem, MNG_NODEFINIT) > 0 && dem.length() > 0) {
        std::string s = dem.c_str();
        if (s.compare(0, 6, "class ") == 0) s = s.substr(6);
        else if (s.compare(0, 7, "struct ") == 0) s = s.substr(7);
        else if (s.compare(0, 6, "union ") == 0) s = s.substr(6);
        return normalize_msvc_nested_class(clean_msvc_decorated_name(s));
    }

    // Manual parse: .?AV or .?AU prefix
    if (raw.length() > 4 && (raw.compare(0, 4, ".?AV") == 0 || raw.compare(0, 4, ".?AU") == 0)) {
        size_t end = raw.find("@@", 4);
        if (end != std::string::npos) {
            std::string n = raw.substr(4, end - 4);
            if (n.length() > 2 && n.compare(0, 2, "?$") == 0) {
                size_t te = n.find('@', 2);
                return (te != std::string::npos) ? n.substr(2, te - 2) : n.substr(2);
            }
            return normalize_msvc_nested_class(n);
        }
    }
    return normalize_msvc_nested_class(raw);
}

inline InheritanceInfo parse_msvc_col(ea_t col, const std::string& derived) {
    InheritanceInfo info;
    info.class_name = derived;
    if (!is_mapped(col)) return info;

    const int ps = get_ptr_size();
    const bool x64 = (ps == 8);

    uint32 sig = get_dword(col);
    if (sig > 2) return info;

    int32 type_rva = get_dword(col + 12);
    int32 class_rva = get_dword(col + 16);

    ea_t base = x64 ? get_imagebase() : 0;
    if (x64 && base == BADADDR) return info;

    ea_t td = x64 ? rva_to_va(base, type_rva) : type_rva;
    ea_t cd = x64 ? rva_to_va(base, class_rva) : class_rva;
    if (td == BADADDR || cd == BADADDR) return info;

    uint32 attrs = get_dword(cd + 4);
    uint32 num = get_dword(cd + 8);
    int32 arr_rva = get_dword(cd + 12);

    info.has_multiple_inheritance = (attrs & 1) != 0;
    info.has_virtual_inheritance = (attrs & 2) != 0;
    if (!num || num > 64) return info;

    ea_t arr = x64 ? rva_to_va(base, arr_rva) : arr_rva;
    if (arr == BADADDR || !is_mapped(arr)) return info;

    for (uint32 i = 0; i < num; ++i) {
        int32 bcd_rva = get_dword(arr + i * 4);
        ea_t bcd = x64 ? rva_to_va(base, bcd_rva) : bcd_rva;
        if (bcd == BADADDR || !is_mapped(bcd)) continue;

        int32 btd_rva = get_dword(bcd);
        int32 mdisp = get_dword(bcd + 8);
        int32 vdisp = get_dword(bcd + 16);

        ea_t btd = x64 ? rva_to_va(base, btd_rva) : btd_rva;
        if (btd == BADADDR || !is_mapped(btd)) continue;

        std::string bc = read_msvc_type_name(btd);
        if (bc.empty() || bc == derived) continue;

        if (i > 0) {
            BaseClassInfo b;
            b.class_name = bc;
            b.offset = mdisp;
            b.is_virtual = (vdisp != -1);
            info.base_classes.push_back(b);
        }
    }
    return info;
}

} // namespace msvc_rtti

inline InheritanceInfo parse_msvc_rtti(ea_t vt, const rtti_detector::RTTIConfig& cfg) {
    InheritanceInfo info;
    const int ps = get_ptr_size();

    ea_t rtti = vt + cfg.rtti_offset;
    if (!is_mapped(rtti)) return info;

    ea_t col;
    if (ps == 8) {
        col = cfg.use_64bit_ptrs ? get_qword(rtti) : msvc_rtti::rva_to_va(get_imagebase(), get_dword(rtti));
    } else {
        col = get_dword(rtti);
    }
    if (col == BADADDR || !is_mapped(col)) return info;

    std::string cls;
    qstring n;
    if (get_name(&n, vt) && strncmp(n.c_str(), "??_7", 4) == 0) {
        const char* end = strstr(n.c_str(), "@@6B@");
        if (end) cls.assign(n.c_str() + 4, end - n.c_str() - 4);
    }
    return msvc_rtti::parse_msvc_col(col, cls);
}

inline InheritanceInfo parse_gcc_rtti(ea_t vt, const rtti_detector::RTTIConfig&) {
    InheritanceInfo info;
    const int ps = get_ptr_size();

    ea_t candidates[] = { read_ptr(vt + ps), read_ptr(vt - ps), read_ptr(vt - 2 * ps) };

    std::string cls;
    qstring n;
    if (get_name(&n, vt)) {
        qstring dem;
        if (demangle_name(&dem, n.c_str(), MNG_NODEFINIT) > 0) {
            const char* d = dem.c_str();
            const char* pos = strstr(d, "vtable for ");
            if (!pos) pos = strstr(d, "vtable for'");
            if (pos) {
                const char* s = pos + 11;
                if (*s == '\'') s++;
                cls = s;
                if (!cls.empty() && cls.back() == '\'') cls.pop_back();
            }
        }
    }

    for (int i = 0; i < 3; ++i) {
        if (candidates[i] == BADADDR || !is_mapped(candidates[i])) continue;
        InheritanceInfo ti = gcc_rtti::parse_gcc_typeinfo(candidates[i], cls);
        if (!ti.base_classes.empty()) return ti;
        if (i == 2) info = ti;
    }
    return info;
}

inline InheritanceInfo parse_vtable_rtti(ea_t vt) {
    const auto& cfg = rtti_detector::get_config(vt);
    return cfg.is_msvc ? parse_msvc_rtti(vt, cfg) : parse_gcc_rtti(vt, cfg);
}

static std::map<ea_t, InheritanceInfo> g_rtti_cache;

inline const InheritanceInfo& get_inheritance_info(ea_t vt) {
    auto it = g_rtti_cache.find(vt);
    if (it != g_rtti_cache.end()) return it->second;
    g_rtti_cache[vt] = parse_vtable_rtti(vt);
    return g_rtti_cache[vt];
}

inline void clear_rtti_cache() { g_rtti_cache.clear(); }

} // namespace rtti_parser
