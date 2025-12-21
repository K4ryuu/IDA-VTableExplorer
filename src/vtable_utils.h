#pragma once
#include <ida.hpp>

namespace vtable_utils {

// Limits
constexpr size_t MIN_CLASS_NAME_LENGTH = 1;
constexpr size_t MAX_CLASS_NAME_LENGTH = 512;
constexpr size_t MAX_COMPONENT_LENGTH = 2048;
constexpr int MAX_RTTI_STRING_LENGTH = 1024;

// Detection
constexpr int MAX_VTABLE_ENTRIES = 2048;
constexpr int CONSECUTIVE_INVALID_THRESHOLD = 5;
constexpr int DEFAULT_VFUNC_START_OFFSET = 2;
constexpr int MAX_VFUNC_SEARCH_DEPTH = 4;

// Buffers
constexpr size_t COMMENT_BUFFER_SIZE = 128;
constexpr size_t FUNCTION_NAME_CACHE_SIZE = 512;
constexpr size_t INDEX_CACHE_SIZE = 16;
constexpr size_t ADDRESS_CACHE_SIZE = 32;
constexpr size_t VTABLE_RESERVE_RATIO = 100;
constexpr size_t ENTRY_RESERVE_SIZE = 64;

// Opcodes
constexpr uint8 OPCODE_PUSH_RBP = 0x55;
constexpr uint8 OPCODE_REX_W = 0x48;
constexpr uint8 OPCODE_REX = 0x40;
constexpr uint8 OPCODE_REX_B = 0x41;

// Colors (BGR)
constexpr uint32 GRAPH_NORMAL = 0x706050;
constexpr uint32 GRAPH_SELECTED = 0xA08070;
constexpr uint32 GRAPH_ABSTRACT = 0x806080;

constexpr uint32 STATUS_INHERITED = 0xA0A0A0;
constexpr uint32 STATUS_OVERRIDDEN = 0x80D080;
constexpr uint32 STATUS_NEW_VIRTUAL = 0x8080D0;
constexpr uint32 STATUS_PURE_TO_IMPL = 0x80D0D0;
constexpr uint32 STATUS_IMPL_TO_PURE = 0xD08080;

constexpr uint32 CLASS_PURE_VIRTUAL = 0xD08080;
constexpr uint32 CLASS_MULTIPLE_INHERIT = 0xD0A080;
constexpr uint32 CLASS_VIRTUAL_INHERIT = 0x8080D0;
constexpr uint32 DEFAULT_BG = 0xFFFFFF;

// Formatters
inline void format_address(char* buf, size_t sz, ea_t addr) {
    qsnprintf(buf, sz, "0x%llX", (unsigned long long)addr);
}

inline void format_sub_address(char* buf, size_t sz, ea_t addr) {
    qsnprintf(buf, sz, "sub_%llX", (unsigned long long)addr);
}

inline void format_index(char* buf, size_t sz, int idx) {
    qsnprintf(buf, sz, "%d", idx);
}

inline void format_function(char* buf, size_t sz, ea_t func) {
    qstring name;
    if (get_name(&name, func) && name.length()) qsnprintf(buf, sz, "%s", name.c_str());
    else format_address(buf, sz, func);
}

// Memory
inline int get_ptr_size() {
    static int ps = inf_is_64bit() ? 8 : 4;
    return ps;
}

inline ea_t read_ptr(ea_t addr) {
    if (!is_mapped(addr)) return BADADDR;
    return get_ptr_size() == 8 ? get_qword(addr) : get_dword(addr);
}

inline int32 read_int32(ea_t addr) {
    return is_mapped(addr) ? get_dword(addr) : 0;
}

inline std::string normalize_msvc_nested_class(const std::string& name) {
    if (name.find('@') == std::string::npos) return name;

    std::vector<std::string> components;
    size_t start = 0;
    size_t pos;

    while ((pos = name.find('@', start)) != std::string::npos) {
        components.push_back(name.substr(start, pos - start));
        start = pos + 1;
    }
    components.push_back(name.substr(start));

    std::string result;
    for (auto it = components.rbegin(); it != components.rend(); ++it) {
        if (it->empty()) continue;
        if (!result.empty()) result += "::";
        result += *it;
    }
    return result;
}

inline std::string clean_msvc_decorated_name(const std::string& name) {
    std::string result = name;

    size_t template_marker = result.rfind("?$");
    if (template_marker != std::string::npos) {
        result = result.substr(template_marker + 2);
    }

    size_t scope_hash = result.find("::$");
    while (scope_hash != std::string::npos) {
        size_t scope_end = result.find("::", scope_hash + 2);
        if (scope_end != std::string::npos) {
            result.erase(scope_hash, scope_end - scope_hash + 2);
        } else {
            break;
        }
        scope_hash = result.find("::$");
    }

    if (!result.empty()) {
        if (result[0] == '$' && result.length() > 3) {
            size_t prefix_end = result.find_first_not_of("0123456789ABCDEFabcdef", 1);
            if (prefix_end != std::string::npos && prefix_end > 1) {
                result = result.substr(prefix_end);
            }
        }
        if (result.length() > 1 && (result[0] == 'V' || result[0] == 'U') && isupper(result[1])) {
            result = result.substr(1);
        }
    }

    return result;
}

} // namespace vtable_utils
