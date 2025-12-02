#pragma once
#include <ida.hpp>
#include <kernwin.hpp>
#include <vector>
#include <string>
#include "vtable_detector.h"
#include "smart_annotator.h"

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

        for (auto &vt : vtables) {
            auto stats = smart_annotator::get_vtable_stats(vt.address, vt.is_windows, sorted_addrs);
            vt.func_count = stats.func_count;
            vt.pure_virtual_count = stats.pure_virtual_count;
        }
        valid = true;
    }

    void invalidate() { valid = false; }
};

static vtable_cache_t g_vtable_cache;

struct func_browser_t : public chooser_t {
protected:
    static constexpr uint32 flags_ = CH_MODAL | CH_KEEP;
    std::vector<smart_annotator::VTableEntry> entries;
    ea_t vtable_addr;

public:
    static constexpr int widths_[] = { 8, 20, 20, 14 };
    static constexpr const char *const header_[] = {
        "Index",
        "Entry Address",
        "Function",
        "Status"
    };

    qstring title_storage;

    func_browser_t(const std::string& cls_name, ea_t vt_addr,
                   const std::vector<smart_annotator::VTableEntry>& ents)
        : chooser_t(flags_, qnumber(widths_), widths_, header_, "Functions"),
          entries(ents), vtable_addr(vt_addr)
    {
        title_storage.sprnt("Functions: %s", cls_name.c_str());
        title = title_storage.c_str();
    }

    virtual size_t idaapi get_count() const override {
        return entries.size();
    }

    virtual void idaapi get_row(
        qstrvec_t *cols,
        int *,
        chooser_item_attrs_t *attrs,
        size_t n) const override
    {
        if (cols == nullptr || n >= entries.size())
            return;

        const auto &entry = entries[n];

        char idx_buf[16];
        qsnprintf(idx_buf, sizeof(idx_buf), "%d", entry.index);
        cols->at(0) = idx_buf;

        char entry_buf[32];
        qsnprintf(entry_buf, sizeof(entry_buf), "0x%llX", (unsigned long long)entry.entry_addr);
        cols->at(1) = entry_buf;

        qstring func_name;
        if (get_name(&func_name, entry.func_ptr) && func_name.length() > 0) {
            cols->at(2) = func_name.c_str();
        } else {
            char func_buf[32];
            qsnprintf(func_buf, sizeof(func_buf), "0x%llX", (unsigned long long)entry.func_ptr);
            cols->at(2) = func_buf;
        }

        if (entry.is_pure_virtual) {
            cols->at(3) = "pure virtual";
            if (attrs)
                attrs->color = 0x8080FF;
        } else {
            cols->at(3) = "";
        }
    }

    virtual cbret_t idaapi enter(size_t n) override {
        if (n >= entries.size())
            return cbret_t(0);

        jumpto(entries[n].func_ptr);
        return cbret_t(n);
    }
};

struct vtable_chooser_t : public chooser_t {
protected:
    static constexpr uint32 flags_ = CH_KEEP | CH_CAN_INS | CH_CAN_DEL | CH_CAN_REFRESH;

public:
    static constexpr int widths_[] = { 55, 18, 10, 14 };
    static constexpr const char *const header_[] = {
        "Class Name",
        "Address",
        "Functions",
        "Type"
    };

    vtable_chooser_t() : chooser_t(flags_, qnumber(widths_), widths_, header_, "VTable Explorer") {
        popup_names[POPUP_INS] = "Annotate All VTables";
        popup_names[POPUP_DEL] = "Browse Functions";
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
        qstrvec_t *cols,
        int *,
        chooser_item_attrs_t *attrs,
        size_t n) const override
    {
        if (cols == nullptr || n >= g_vtable_cache.vtables.size())
            return;

        const VTableInfo &vt = g_vtable_cache.vtables[n];

        std::string name_display = vt.class_name;
        if (vt.pure_virtual_count > 0) {
            name_display += " [abstract]";
            if (attrs)
                attrs->color = 0xFFB080;
        }
        cols->at(0) = name_display.c_str();

        char addr_buf[32];
        qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)vt.address);
        cols->at(1) = addr_buf;

        char count_buf[16];
        if (vt.pure_virtual_count > 0) {
            qsnprintf(count_buf, sizeof(count_buf), "%d (%d pv)", vt.func_count, vt.pure_virtual_count);
        } else {
            qsnprintf(count_buf, sizeof(count_buf), "%d", vt.func_count);
        }
        cols->at(2) = count_buf;
        cols->at(3) = vt.is_windows ? "Windows/MSVC" : "Linux/GCC";
    }

    virtual cbret_t idaapi enter(size_t n) override {
        if (n >= g_vtable_cache.vtables.size())
            return cbret_t(0);

        const VTableInfo &vt = g_vtable_cache.vtables[n];
        int count = smart_annotator::annotate_vtable(vt.address, vt.is_windows, g_vtable_cache.sorted_addrs, vt.class_name);

        jumpto(vt.address);

        info("VTable Annotation Complete\n\n"
             "Class: %s\n"
             "Address: 0x%llX\n"
             "Functions annotated: %d%s",
             vt.class_name.c_str(),
             (unsigned long long)vt.address,
             count,
             vt.pure_virtual_count > 0 ? "\n(Abstract class - has pure virtual functions)" : "");

        return cbret_t(n);
    }

    virtual cbret_t idaapi del(size_t n) override {
        if (n >= g_vtable_cache.vtables.size())
            return cbret_t(0);

        const VTableInfo &vt = g_vtable_cache.vtables[n];
        auto entries = smart_annotator::get_vtable_entries(vt.address, vt.is_windows, g_vtable_cache.sorted_addrs);

        if (entries.empty()) {
            warning("No functions found in vtable");
            return cbret_t(n);
        }

        func_browser_t browser(vt.class_name, vt.address, entries);
        browser.choose();

        return cbret_t(n);
    }

    virtual cbret_t idaapi ins(ssize_t) override {
        if (g_vtable_cache.vtables.empty())
            return cbret_t(0);

        show_wait_box("Annotating all vtables...");

        int total_funcs = 0;
        int total_vtables = 0;

        for (const auto &vt : g_vtable_cache.vtables) {
            int count = smart_annotator::annotate_vtable(vt.address, vt.is_windows, g_vtable_cache.sorted_addrs, vt.class_name);
            total_funcs += count;
            total_vtables++;

            if (user_cancelled()) {
                hide_wait_box();
                info("Annotation cancelled.\n\n"
                     "VTables annotated: %d / %d\n"
                     "Functions annotated: %d",
                     total_vtables, (int)g_vtable_cache.vtables.size(), total_funcs);
                return cbret_t(0);
            }
        }

        hide_wait_box();

        info("All VTables Annotated!\n\n"
             "VTables processed: %d\n"
             "Total functions annotated: %d",
             total_vtables, total_funcs);

        return cbret_t(0);
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
