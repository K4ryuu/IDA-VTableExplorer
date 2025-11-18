#pragma once
#include <ida.hpp>
#include <kernwin.hpp>
#include <vector>
#include <string>
#include "vtable_detector.h"
#include "smart_annotator.h"

struct vtable_chooser_t : public chooser_t {
protected:
    static constexpr uint32 flags_ = CH_MODAL | CH_KEEP;
    std::vector<VTableInfo> vtables;

public:
    static constexpr int widths_[] = { 70, 18, 14 };
    static constexpr const char *const header_[] = {
        "Class Name",
        "Address",
        "Type"
    };

    vtable_chooser_t() : chooser_t(flags_, qnumber(widths_), widths_, header_, "VTable Explorer") {
        vtables = vtable_detector::find_vtables();
    }

    virtual size_t idaapi get_count() const override {
        return vtables.size();
    }

    virtual void idaapi get_row(
        qstrvec_t *cols,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
    {
        if (n >= vtables.size())
            return;

        const VTableInfo &vt = vtables[n];

        cols->at(0) = vt.class_name.c_str();

        char addr_buf[32];
        qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)vt.address);
        cols->at(1) = addr_buf;

        cols->at(2) = vt.is_windows ? "Windows/MSVC" : "Linux/GCC";
    }

    virtual cbret_t idaapi enter(size_t n) override {
        if (n >= vtables.size())
            return cbret_t(0);

        const VTableInfo &vt = vtables[n];

        std::vector<ea_t> all_addrs;
        for (const auto &v : vtables)
            all_addrs.push_back(v.address);

        // Call enhanced annotator with class name
        int count = smart_annotator::annotate_vtable(vt.address, vt.is_windows, all_addrs, vt.class_name);

        jumpto(vt.address);

        info("VTable Annotation Complete\n\n"
             "Class: %s\n"
             "Address: 0x%llX\n"
             "Functions annotated: %d",
             vt.class_name.c_str(),
             (unsigned long long)vt.address,
             count);

        return cbret_t(n);
    }

};

inline void show_vtable_chooser() {
    vtable_chooser_t chooser;
    chooser.choose();
}
