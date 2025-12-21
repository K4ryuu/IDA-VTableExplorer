#pragma once
#include <ida.hpp>
#include <kernwin.hpp>
#include <vector>
#include <string>
#include <map>
#include <set>
#include "vtable_detector.h"
#include "smart_annotator.h"
#include "rtti_parser.h"
#include "vtable_comparison.h"
#include "inheritance_graph.h"
#include "vtable_utils.h"

struct vtable_cache_t {
    std::vector<VTableInfo> vtables;
    std::vector<ea_t> sorted_addrs;
    bool valid = false;

    void refresh() {
        vtables = vtable_detector::find_vtables();
        sorted_addrs.clear();
        sorted_addrs.reserve(vtables.size());
        for (const auto &v : vtables)
            sorted_addrs.push_back(v.address);
        std::sort(sorted_addrs.begin(), sorted_addrs.end());

        std::map<std::string, ea_t> class_to_vtable;
        for (const auto &vt : vtables) {
            class_to_vtable[vt.class_name] = vt.address;
        }

        for (auto &vt : vtables) {
            auto stats = smart_annotator::get_vtable_stats(vt.address, vt.is_windows, sorted_addrs);
            vt.func_count = stats.func_count;
            vt.pure_virtual_count = stats.pure_virtual_count;

            const auto& inherit_info = rtti_parser::get_inheritance_info(vt.address);
            vt.base_classes.clear();
            for (const auto& base : inherit_info.base_classes) {
                vt.base_classes.push_back(base.class_name);
            }
            vt.has_multiple_inheritance = inherit_info.has_multiple_inheritance;
            vt.has_virtual_inheritance = inherit_info.has_virtual_inheritance;

            if (!vt.base_classes.empty()) {
                vt.parent_class = vt.base_classes[0];
            }

            vt.derived_classes.clear();
            vt.derived_count = 0;
        }

        std::map<std::string, std::vector<std::string>> base_to_derived;
        for (const auto &vt : vtables) {
            for (const auto& base : vt.base_classes) {
                base_to_derived[base].push_back(vt.class_name);
            }
        }

        std::vector<VTableInfo> intermediate_classes;
        std::set<std::string> seen_intermediate;

        for (const auto &vt : vtables) {
            for (size_t i = 0; i < vt.base_classes.size(); ++i) {
                const std::string& base = vt.base_classes[i];
                if (class_to_vtable.find(base) == class_to_vtable.end() &&
                    seen_intermediate.find(base) == seen_intermediate.end()) {

                    seen_intermediate.insert(base);

                    ea_t parent_vtable = BADADDR;
                    std::string parent_name;
                    for (size_t j = i + 1; j < vt.base_classes.size(); ++j) {
                        auto it = class_to_vtable.find(vt.base_classes[j]);
                        if (it != class_to_vtable.end()) {
                            parent_vtable = it->second;
                            parent_name = vt.base_classes[j];
                            break;
                        }
                    }

                    VTableInfo intermediate;
                    intermediate.address = BADADDR;
                    intermediate.class_name = base;
                    intermediate.display_name = parent_name.empty() ?
                        base :
                        parent_name + "::" + base;
                    intermediate.is_windows = vt.is_windows;
                    intermediate.func_count = 0;
                    intermediate.pure_virtual_count = 0;
                    intermediate.derived_count = 0;
                    intermediate.has_multiple_inheritance = false;
                    intermediate.has_virtual_inheritance = false;
                    intermediate.is_intermediate = true;
                    intermediate.parent_vtable_addr = parent_vtable;
                    intermediate.parent_class = parent_name;

                    if (parent_vtable != BADADDR) {
                        auto stats = smart_annotator::get_vtable_stats(parent_vtable, vt.is_windows, sorted_addrs);
                        intermediate.func_count = stats.func_count;
                        intermediate.pure_virtual_count = stats.pure_virtual_count;
                    }

                    auto derived_it = base_to_derived.find(base);
                    if (derived_it != base_to_derived.end()) {
                        intermediate.derived_classes = derived_it->second;
                        intermediate.derived_count = static_cast<int>(derived_it->second.size());
                    }

                    intermediate_classes.push_back(std::move(intermediate));
                    class_to_vtable[base] = BADADDR;
                }
            }
        }

        for (auto& inter : intermediate_classes) {
            vtables.push_back(std::move(inter));
        }

        for (auto &vt : vtables) {
            if (!vt.is_intermediate) {
                auto it = base_to_derived.find(vt.class_name);
                if (it != base_to_derived.end()) {
                    vt.derived_classes = it->second;
                    vt.derived_count = static_cast<int>(it->second.size());
                }
            }
        }

        std::sort(vtables.begin(), vtables.end(),
            [](const VTableInfo& a, const VTableInfo& b) { return a.class_name < b.class_name; });

        valid = true;
    }

    void invalidate() { valid = false; }
};

static vtable_cache_t g_vtable_cache;

struct func_browser_t : public chooser_t {
protected:
    static constexpr uint32 flags_ = CH_KEEP;
    std::vector<smart_annotator::VTableEntry> entries;
    ea_t vtable_addr;
    std::map<int, vtable_comparison::OverrideStatus> status_map;

    mutable char idx_cache[vtable_utils::INDEX_CACHE_SIZE];
    mutable char entry_addr_cache[vtable_utils::ADDRESS_CACHE_SIZE];
    mutable char func_addr_cache[vtable_utils::FUNCTION_NAME_CACHE_SIZE];

public:
    static constexpr int widths_[] = { 8, 20, 20, 14 };
    static constexpr const char *const header_[] = {
        "Index", "Entry Address", "Function", "Status"
    };

    qstring title_storage;

    func_browser_t(const std::string& cls_name, ea_t vt_addr,
                   const std::vector<smart_annotator::VTableEntry>& ents,
                   const vtable_comparison::VTableComparison* comp = nullptr)
        : chooser_t(flags_, qnumber(widths_), widths_, header_, "Functions"),
          entries(ents), vtable_addr(vt_addr)
    {
        title_storage.sprnt("Functions: %s", cls_name.c_str());
        title = title_storage.c_str();
        popup_names[POPUP_INS] = "Jump to Function";

        if (comp) {
            for (const auto& entry : comp->entries) {
                status_map[entry.index] = entry.status;
            }
        }
    }

    virtual size_t idaapi get_count() const override {
        return entries.size();
    }

    virtual void idaapi get_row(
        qstrvec_t *cols, int *, chooser_item_attrs_t *attrs, size_t n) const override
    {
        if (cols == nullptr || n >= entries.size()) return;

        const auto &entry = entries[n];

        vtable_utils::format_index(idx_cache, sizeof(idx_cache), entry.index);
        cols->at(0) = idx_cache;

        vtable_utils::format_address(entry_addr_cache, sizeof(entry_addr_cache), entry.entry_addr);
        cols->at(1) = entry_addr_cache;

        vtable_utils::format_function(func_addr_cache, sizeof(func_addr_cache), entry.func_ptr);
        cols->at(2) = func_addr_cache;

        auto status_it = status_map.find(entry.index);
        if (status_it != status_map.end()) {
            cols->at(3) = vtable_comparison::get_status_string(status_it->second);
            if (attrs) attrs->color = vtable_comparison::get_status_color(status_it->second);
        } else if (entry.is_pure_virtual) {
            cols->at(3) = "pure virtual";
            if (attrs) attrs->color = vtable_utils::CLASS_PURE_VIRTUAL;
        } else {
            cols->at(3) = "";
        }
    }

    virtual cbret_t idaapi enter(size_t n) override {
        if (n >= entries.size()) return cbret_t(0);
        jumpto(entries[n].func_ptr);
        return cbret_t(0);
    }

    virtual cbret_t idaapi ins(ssize_t n) override {
        size_t idx = (n < 0) ? 0 : n;
        if (idx >= entries.size()) return cbret_t(0);
        jumpto(entries[idx].func_ptr);
        return cbret_t(0);
    }

    virtual const void *idaapi get_obj_id(size_t *len) const override {
        *len = sizeof(vtable_addr);
        return &vtable_addr;
    }
};

struct comparison_browser_t : public chooser_t {
protected:
    static constexpr uint32 flags_ = CH_KEEP | CH_CAN_REFRESH;
    vtable_comparison::VTableComparison comparison;
    bool show_inherited;

    mutable char idx_cache[vtable_utils::INDEX_CACHE_SIZE];
    mutable char base_addr_cache[vtable_utils::ADDRESS_CACHE_SIZE];
    mutable char base_func_cache[vtable_utils::FUNCTION_NAME_CACHE_SIZE];
    mutable char derived_addr_cache[vtable_utils::ADDRESS_CACHE_SIZE];
    mutable char derived_func_cache[vtable_utils::FUNCTION_NAME_CACHE_SIZE];

    mutable std::vector<size_t> filtered_indices;
    mutable bool cache_valid = false;

public:
    static constexpr int widths_[] = { 6, 18, 22, 18, 22, 14 };
    static constexpr const char *const header_[] = {
        "Index", "Base Function", "Base Address",
        "Derived Function", "Derived Address", "Status"
    };

    qstring title_storage;

    comparison_browser_t(const vtable_comparison::VTableComparison& comp, bool show_all = false)
        : chooser_t(flags_, qnumber(widths_), widths_, header_, "VTable Comparison"),
          comparison(comp), show_inherited(show_all)
    {
        title_storage.sprnt("Compare: %s → %s",
                           comp.derived_class.c_str(),
                           comp.base_class.c_str());
        title = title_storage.c_str();
        popup_names[POPUP_INS] = "Jump to Derived Function";
        popup_names[POPUP_DEL] = "Jump to Base Function";
        popup_names[POPUP_REFRESH] = show_inherited ? "Hide Inherited" : "Show All";
        rebuild_filtered_cache();  // Build cache on construction
    }

private:
    void rebuild_filtered_cache() const {
        filtered_indices.clear();
        filtered_indices.reserve(comparison.entries.size());

        for (size_t i = 0; i < comparison.entries.size(); ++i) {
            if (show_inherited || comparison.entries[i].status != vtable_comparison::OverrideStatus::INHERITED) {
                filtered_indices.push_back(i);
            }
        }
        cache_valid = true;
    }

public:
    virtual size_t idaapi get_count() const override {
        if (!cache_valid) rebuild_filtered_cache();
        return filtered_indices.size();
    }

    virtual void idaapi get_row(
        qstrvec_t *cols, int *, chooser_item_attrs_t *attrs, size_t n) const override
    {
        if (cols == nullptr) return;
        if (!cache_valid) rebuild_filtered_cache();
        if (n >= filtered_indices.size()) {
            return;
        }

        size_t entry_idx = filtered_indices[n];
        const auto& entry = comparison.entries[entry_idx];

        vtable_utils::format_index(idx_cache, sizeof(idx_cache), entry.index);
        cols->at(0) = idx_cache;

        if (!entry.base_func_name.empty()) {
            qsnprintf(base_func_cache, sizeof(base_func_cache), "%s", entry.base_func_name.c_str());
            cols->at(1) = base_func_cache;
        } else if (entry.base_func_ptr != BADADDR) {
            vtable_utils::format_sub_address(base_func_cache, sizeof(base_func_cache), entry.base_func_ptr);
            cols->at(1) = base_func_cache;
        } else {
            cols->at(1) = "-";
        }

        if (entry.base_func_ptr != BADADDR) {
            vtable_utils::format_address(base_addr_cache, sizeof(base_addr_cache), entry.base_func_ptr);
            cols->at(2) = base_addr_cache;
        } else {
            cols->at(2) = "-";
        }

        if (!entry.derived_func_name.empty()) {
            qsnprintf(derived_func_cache, sizeof(derived_func_cache), "%s", entry.derived_func_name.c_str());
            cols->at(3) = derived_func_cache;
        } else {
            vtable_utils::format_sub_address(derived_func_cache, sizeof(derived_func_cache), entry.derived_func_ptr);
            cols->at(3) = derived_func_cache;
        }

        vtable_utils::format_address(derived_addr_cache, sizeof(derived_addr_cache), entry.derived_func_ptr);
        cols->at(4) = derived_addr_cache;

        cols->at(5) = vtable_comparison::get_status_string(entry.status);
        if (attrs) attrs->color = vtable_comparison::get_status_color(entry.status);
    }

    virtual cbret_t idaapi enter(size_t n) override {
        if (!cache_valid) rebuild_filtered_cache();
        if (n >= filtered_indices.size()) return cbret_t(0);

        const auto& entry = comparison.entries[filtered_indices[n]];

        if (entry.derived_func_ptr != BADADDR) {
            jumpto(entry.derived_func_ptr);
        }

        return cbret_t(0);
    }

    virtual cbret_t idaapi ins(ssize_t n) override {
        if (n < 0 || !cache_valid) rebuild_filtered_cache();
        size_t idx = (n < 0) ? 0 : n;
        if (idx >= filtered_indices.size()) return cbret_t(0);

        const auto& entry = comparison.entries[filtered_indices[idx]];

        if (entry.derived_func_ptr != BADADDR) {
            jumpto(entry.derived_func_ptr);
        }

        return cbret_t(n);
    }

    virtual cbret_t idaapi del(ssize_t n) {
        if (n < 0 || !cache_valid) rebuild_filtered_cache();
        size_t idx = (n < 0) ? 0 : n;
        if (idx >= filtered_indices.size()) return cbret_t(0);

        const auto& entry = comparison.entries[filtered_indices[idx]];

        if (entry.base_func_ptr != BADADDR) {
            jumpto(entry.base_func_ptr);
        }

        return cbret_t(n);
    }

    virtual cbret_t idaapi refresh(ssize_t) override {
        show_inherited = !show_inherited;
        popup_names[POPUP_REFRESH] = show_inherited ? "Hide Inherited" : "Show All";
        cache_valid = false;  // Invalidate cache on filter change
        return cbret_t(ALL_CHANGED);
    }

    virtual const void *idaapi get_obj_id(size_t *len) const override {
        static const char id[] = "VTableComparison";
        *len = sizeof(id);
        return id;
    }
};

struct vtable_chooser_t : public chooser_t {
protected:
    static constexpr uint32 flags_ = CH_KEEP | CH_CAN_REFRESH;
    mutable size_t last_selection = 0;

public:
    static constexpr int widths_[] = { 30, 25, 18, 10, 12 };
    static constexpr const char *const header_[] = {
        "Class Name", "Base Classes", "Address",
        "Functions", "Status"
    };

    vtable_chooser_t() : chooser_t(flags_, qnumber(widths_), widths_, header_, "VTable Explorer") {
        popup_names[POPUP_REFRESH] = "Refresh VTables";

        if (!g_vtable_cache.valid) {
            try {
                g_vtable_cache.refresh();
            } catch (...) {
                g_vtable_cache.vtables.clear();
            }
        }
    }

    virtual size_t idaapi get_count() const override {
        return g_vtable_cache.vtables.size();
    }

    virtual void idaapi get_row(
        qstrvec_t *cols, int *, chooser_item_attrs_t *attrs, size_t n) const override
    {
        if (cols == nullptr || n >= g_vtable_cache.vtables.size()) return;

        const VTableInfo &vt = g_vtable_cache.vtables[n];

        cols->at(0) = vt.display_name.c_str();

        if (!vt.base_classes.empty()) {
            cols->at(1) = vt.base_classes[0].c_str();
        } else if (!vt.parent_class.empty()) {
            cols->at(1) = vt.parent_class.c_str();
        } else {
            cols->at(1) = "";
        }

        char addr_buf[32];
        if (vt.is_intermediate) {
            if (vt.parent_vtable_addr != BADADDR) {
                qsnprintf(addr_buf, sizeof(addr_buf), "-> 0x%llX", (unsigned long long)vt.parent_vtable_addr);
            } else {
                qsnprintf(addr_buf, sizeof(addr_buf), "(inlined)");
            }
        } else {
            qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)vt.address);
        }
        cols->at(2) = addr_buf;

        char count_buf[16];
        if (vt.is_intermediate) {
            if (vt.func_count > 0) {
                qsnprintf(count_buf, sizeof(count_buf), "~%d", vt.func_count);
            } else {
                qsnprintf(count_buf, sizeof(count_buf), "-");
            }
        } else if (vt.pure_virtual_count > 0) {
            qsnprintf(count_buf, sizeof(count_buf), "%d (%d pv)", vt.func_count, vt.pure_virtual_count);
        } else {
            qsnprintf(count_buf, sizeof(count_buf), "%d", vt.func_count);
        }
        cols->at(3) = count_buf;

        const char* status = "";
        if (vt.is_intermediate) {
            status = "Intermediate";
        } else if (vt.pure_virtual_count > 0) {
            status = "Abstract";
        } else if (!vt.base_classes.empty()) {
            status = "Has Base";
        } else {
            status = "Root";
        }
        cols->at(4) = status;

        if (vt.is_intermediate) {
            if (attrs) attrs->color = 0xA0A0A0;
        } else if (vt.pure_virtual_count > 0) {
            if (attrs) attrs->color = vtable_utils::CLASS_MULTIPLE_INHERIT;
        } else if (vt.base_classes.empty() && !vt.is_intermediate) {
            if (attrs) attrs->color = vtable_utils::CLASS_VIRTUAL_INHERIT;
        }
    }

    virtual cbret_t idaapi enter(size_t n) override {
        if (n >= g_vtable_cache.vtables.size()) return cbret_t(0);

        last_selection = n;
        const VTableInfo &vt = g_vtable_cache.vtables[n];

        if (vt.is_intermediate) {
            if (vt.parent_vtable_addr != BADADDR) {
                jumpto(vt.parent_vtable_addr);
                info("Intermediate Class\n\n"
                     "Class: %s\nNo vtable symbol (inlined by compiler)\n"
                     "Jumped to parent: %s @ 0x%llX",
                     vt.class_name.c_str(), vt.parent_class.c_str(),
                     (unsigned long long)vt.parent_vtable_addr);
            } else {
                info("Intermediate Class\n\n"
                     "Class: %s\nNo vtable symbol (inlined by compiler)\n"
                     "No parent vtable found",
                     vt.class_name.c_str());
            }
            return cbret_t(n);
        }

        int count = smart_annotator::annotate_vtable(vt.address, vt.is_windows, g_vtable_cache.sorted_addrs);
        jumpto(vt.address);

        info("VTable Annotation Complete\n\n"
             "Class: %s\nAddress: 0x%llX\nFunctions annotated: %d%s",
             vt.class_name.c_str(), (unsigned long long)vt.address, count,
             vt.pure_virtual_count > 0 ? "\n(Abstract class)" : "");

        return cbret_t(n);
    }

    virtual cbret_t idaapi refresh(ssize_t) override {
        show_wait_box("Scanning vtables...");
        g_vtable_cache.refresh();
        hide_wait_box();
        return cbret_t(ALL_CHANGED);
    }

    virtual const void *idaapi get_obj_id(size_t *len) const override {
        static const char id[] = "VTableExplorer";
        *len = sizeof(id);
        return id;
    }

    size_t get_current_selection() const { return last_selection; }

    void show_tree_for_selection(size_t n) {
        if (n >= g_vtable_cache.vtables.size()) {
            warning("Invalid selection: %zu", n);
            return;
        }
        const VTableInfo& vt = g_vtable_cache.vtables[n];
        inheritance_graph::show_inheritance_graph(
            vt.class_name, vt.address, vt.is_windows, &g_vtable_cache.vtables
        );
    }

    void show_tree_for_current() {
        if (last_selection >= g_vtable_cache.vtables.size()) {
            warning("No vtable selected");
            return;
        }
        const VTableInfo& vt = g_vtable_cache.vtables[last_selection];
        inheritance_graph::show_inheritance_graph(
            vt.class_name, vt.address, vt.is_windows, &g_vtable_cache.vtables
        );
    }

private:
    bool select_base_class(const std::vector<std::string>& base_classes,
                          std::string& selected_base) const {
        if (base_classes.size() == 1) {
            selected_base = base_classes[0];
            return true;
        }

        qstring selection_text = "Select base class:\n\n";
        for (size_t i = 0; i < base_classes.size(); ++i) {
            selection_text.cat_sprnt("%d. %s\n", (int)i, base_classes[i].c_str());
        }
        selection_text.cat_sprnt("\nEnter number (0-%d): ", (int)(base_classes.size() - 1));

        qstring choice_str;
        if (!ask_str(&choice_str, HIST_IDENT, "%s", selection_text.c_str())) {
            return false;
        }

        int base_selection = atoi(choice_str.c_str());

        if (base_selection < 0 || base_selection >= (int)base_classes.size()) {
            warning("Invalid choice: %d. Must be between 0 and %d",
                   base_selection, (int)(base_classes.size() - 1));
            return false;
        }

        selected_base = base_classes[base_selection];
        return true;
    }

    void show_comparison_for_vtable_index(size_t n) {
        if (n >= g_vtable_cache.vtables.size()) {
            warning("Invalid selection");
            return;
        }

        const VTableInfo& vt = g_vtable_cache.vtables[n];

        if (vt.is_intermediate) {
            if (vt.parent_vtable_addr == BADADDR || vt.parent_class.empty()) {
                warning("Intermediate class %s has no parent vtable to compare",
                       vt.class_name.c_str());
                return;
            }

            ea_t parent_parent_vtable = BADADDR;
            std::string parent_parent_name;

            for (const auto& other : g_vtable_cache.vtables) {
                if (other.class_name == vt.parent_class && !other.is_intermediate) {
                    if (!other.base_classes.empty()) {
                        parent_parent_name = other.base_classes[0];
                        parent_parent_vtable = vtable_comparison::find_vtable_by_class_name(
                            parent_parent_name, g_vtable_cache.vtables);
                    }
                    break;
                }
            }

            if (parent_parent_vtable == BADADDR) {
                info("Intermediate Class Comparison\n\n"
                     "Class: %s (uses parent's vtable)\n"
                     "Parent: %s @ 0x%llX\n\n"
                     "No grandparent vtable found for comparison.\n"
                     "Use 'Browse Functions' to see inherited functions.",
                     vt.class_name.c_str(), vt.parent_class.c_str(),
                     (unsigned long long)vt.parent_vtable_addr);
                return;
            }

            auto comp = vtable_comparison::compare_vtables(
                vt.parent_vtable_addr, parent_parent_vtable, vt.is_windows,
                g_vtable_cache.sorted_addrs,
                vt.class_name + " (via " + vt.parent_class + ")", parent_parent_name
            );

            if (comp.entries.empty()) {
                warning("No vtable entries found for comparison");
                return;
            }

            comparison_browser_t *browser = new comparison_browser_t(comp, false);
            browser->choose();
            return;
        }

        if (vt.base_classes.empty()) {
            warning("No base classes found for %s\n\n"
                   "This class either:\n"
                   "- Has no inheritance\n"
                   "- Was compiled without RTTI\n"
                   "- Has stripped RTTI information",
                   vt.class_name.c_str());
            return;
        }

        std::string selected_base;
        if (!select_base_class(vt.base_classes, selected_base)) {
            return;
        }

        ea_t base_vtable = vtable_comparison::find_vtable_by_class_name(
            selected_base, g_vtable_cache.vtables);

        if (base_vtable == BADADDR) {
            warning("Could not find vtable for base class: %s", selected_base.c_str());
            return;
        }

        auto comp = vtable_comparison::compare_vtables(
            vt.address, base_vtable, vt.is_windows,
            g_vtable_cache.sorted_addrs,
            vt.class_name, selected_base
        );

        if (comp.entries.empty()) {
            warning("No vtable entries found for comparison");
            return;
        }

        comparison_browser_t *browser = new comparison_browser_t(comp, false);
        browser->choose();
    }

public:
    void show_compare_for_selection(size_t n) {
        show_comparison_for_vtable_index(n);
    }

    void show_compare_for_current() {
        show_comparison_for_vtable_index(last_selection);
    }
};

static vtable_chooser_t* g_chooser = nullptr;

inline void show_vtable_chooser() {
    if (!g_chooser) {
        g_chooser = new vtable_chooser_t();
    }
    g_chooser->choose();
}

inline void close_vtable_chooser() {
    if (g_chooser) {
        delete g_chooser;
        g_chooser = nullptr;
    }
    g_vtable_cache.invalidate();
}

inline void show_inheritance_tree_action(action_activation_ctx_t* ctx) {
    if (!g_chooser) {
        warning("VTable Explorer not open.\nPlease open it first with Cmd/Ctrl+Shift+V");
        return;
    }

    if (ctx && !ctx->chooser_selection.empty()) {
        g_chooser->show_tree_for_selection(ctx->chooser_selection[0]);
    } else {
        g_chooser->show_tree_for_current();
    }
}

inline void show_compare_base_action(action_activation_ctx_t* ctx) {
    if (!g_chooser) {
        warning("VTable Explorer not open.\nPlease open it first with Cmd/Ctrl+Shift+V");
        return;
    }

    if (ctx && !ctx->chooser_selection.empty()) {
        g_chooser->show_compare_for_selection(ctx->chooser_selection[0]);
    } else {
        g_chooser->show_compare_for_current();
    }
}

inline void funcbrowser_jump_action(action_activation_ctx_t* ctx) {
    if (!ctx || !ctx->widget) return;

    qstring title;
    get_widget_title(&title, ctx->widget);

    func_browser_t* browser = (func_browser_t*)get_chooser_obj(title.c_str());
    if (browser && !ctx->chooser_selection.empty()) {
        browser->ins(ctx->chooser_selection[0]);
    }
}

inline void compbrowser_jump_derived_action(action_activation_ctx_t* ctx) {
    if (!ctx || !ctx->widget) return;

    qstring title;
    get_widget_title(&title, ctx->widget);

    comparison_browser_t* browser = (comparison_browser_t*)get_chooser_obj(title.c_str());
    if (browser && !ctx->chooser_selection.empty()) {
        browser->ins(ctx->chooser_selection[0]);
    }
}

inline void compbrowser_jump_base_action(action_activation_ctx_t* ctx) {
    if (!ctx || !ctx->widget) return;

    qstring title;
    get_widget_title(&title, ctx->widget);

    comparison_browser_t* browser = (comparison_browser_t*)get_chooser_obj(title.c_str());
    if (browser && !ctx->chooser_selection.empty()) {
        browser->del(ctx->chooser_selection[0]);
    }
}

inline void compbrowser_toggle_action(action_activation_ctx_t* ctx) {
    if (!ctx || !ctx->widget) return;

    qstring title;
    get_widget_title(&title, ctx->widget);

    comparison_browser_t* browser = (comparison_browser_t*)get_chooser_obj(title.c_str());
    if (browser) {
        browser->refresh(0);
    }
}
