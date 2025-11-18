#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "vtable_chooser.h"

struct vtable_explorer_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        show_vtable_chooser();
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

static vtable_explorer_action_t ah_explorer;

static ssize_t idaapi ui_notification(void*, int notification_code, va_list va) {
    if (notification_code == ui_finish_populating_widget_popup) {
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup = va_arg(va, TPopupMenu*);

        if (get_widget_type(widget) == BWN_DISASM || get_widget_type(widget) == BWN_PSEUDOCODE) {
            attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
            attach_action_to_popup(widget, popup, "vtable:explorer", nullptr, SETMENU_APP);
        }
    }
    return 0;
}

struct vtable_plugin_ctx_t : public plugmod_t {
    virtual bool idaapi run(size_t) override {
        show_vtable_chooser();
        return true;
    }

    virtual ~vtable_plugin_ctx_t() {
        unregister_action("vtable:explorer");
        unhook_from_notification_point(HT_UI, ui_notification, nullptr);
    }
};

plugmod_t* idaapi init() {
    msg("[VTableExplorer] Plugin loaded v1.0.1\n");

    action_desc_t desc_explorer = ACTION_DESC_LITERAL(
        "vtable:explorer",
        "VTable Explorer",
        &ah_explorer,
#ifdef __MAC__
        "Cmd+Shift+V",
#else
        "Ctrl+Shift+V",
#endif
        "Open VTable Explorer with searchable class list",
        -1
    );

    register_action(desc_explorer);

    hook_to_notification_point(HT_UI, ui_notification, nullptr);

    return new vtable_plugin_ctx_t;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "VTable Explorer v1.0.1 - Symbol-based vtable detection & annotation",
    "https://github.com/K4ryuu/IDA-VTableExplorer",
    "VTableExplorer",
#ifdef __MAC__
    "Cmd-Shift-V"
#else
    "Ctrl-Shift-V"
#endif
};
