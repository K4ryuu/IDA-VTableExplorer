#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "vtable_chooser.h"

#define PLUGIN_VERSION "1.2.2"
#define PLUGIN_DESCRIPTION "VTable Explorer v" PLUGIN_VERSION " - Graph-based inheritance view & high quality vtable analysis"

struct vtable_explorer_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        show_vtable_chooser();
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct vtable_tree_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        show_inheritance_tree_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct vtable_compare_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        show_compare_base_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct funcbrowser_jump_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        funcbrowser_jump_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct compbrowser_jump_derived_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        compbrowser_jump_derived_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct compbrowser_jump_base_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        compbrowser_jump_base_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct compbrowser_toggle_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        compbrowser_toggle_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct browse_functions_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        browse_functions_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

struct annotate_all_action_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        annotate_all_action(ctx);
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

static vtable_explorer_action_t ah_explorer;
static vtable_tree_action_t ah_tree;
static vtable_compare_action_t ah_compare;
static funcbrowser_jump_action_t ah_funcjump;
static compbrowser_jump_derived_action_t ah_compjump_derived;
static compbrowser_jump_base_action_t ah_compjump_base;
static compbrowser_toggle_action_t ah_comptoggle;
static browse_functions_action_t ah_browse_funcs;
static annotate_all_action_t ah_annotate_all;

struct ui_event_listener_t : public event_listener_t {
    virtual ssize_t idaapi on_event(ssize_t code, va_list va) override {
        if (code == ui_finish_populating_widget_popup) {
            TWidget* widget = va_arg(va, TWidget*);
            TPopupMenu* popup = va_arg(va, TPopupMenu*);

            if (get_widget_type(widget) == BWN_DISASM || get_widget_type(widget) == BWN_PSEUDOCODE) {
                attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
                attach_action_to_popup(widget, popup, "vtable:explorer", nullptr, SETMENU_APP);
            }
            else if (get_widget_type(widget) == BWN_CHOOSER) {
                qstring title;
                get_widget_title(&title, widget);
                if (title == "VTable Explorer") {
                    attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "vtable:browse_funcs", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "vtable:tree", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "vtable:compare", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "vtable:annotate_all", nullptr, SETMENU_APP);
                }
                else if (title.find("Functions:") == 0) {
                    attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "funcbrowser:jump", nullptr, SETMENU_APP);
                }
                else if (title.find("Compare:") == 0 || title == "VTable Comparison") {
                    attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "compbrowser:jump_derived", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "compbrowser:jump_base", nullptr, SETMENU_APP);
                    attach_action_to_popup(widget, popup, "compbrowser:toggle", nullptr, SETMENU_APP);
                }
            }
        }
        return 0;
    }
};

static ui_event_listener_t ui_listener;

struct vtable_plugin_ctx_t : public plugmod_t {
    virtual bool idaapi run(size_t) override {
        return true;
    }

    virtual ~vtable_plugin_ctx_t() {
        unregister_action("vtable:explorer");
        unregister_action("vtable:tree");
        unregister_action("vtable:compare");
        unregister_action("vtable:browse_funcs");
        unregister_action("vtable:annotate_all");
        unregister_action("funcbrowser:jump");
        unregister_action("compbrowser:jump_derived");
        unregister_action("compbrowser:jump_base");
        unregister_action("compbrowser:toggle");
        unhook_event_listener(HT_UI, &ui_listener);
    }
};

plugmod_t* idaapi init() {
    action_desc_t desc_explorer = ACTION_DESC_LITERAL(
        "vtable:explorer",
        "VTable Explorer",
        &ah_explorer,
        nullptr,
        "Open VTable Explorer with searchable class list",
        -1
    );

    action_desc_t desc_tree = ACTION_DESC_LITERAL(
        "vtable:tree",
        "Show Inheritance Tree",
        &ah_tree,
        nullptr,
        "Show inheritance graph for selected class",
        -1
    );

    action_desc_t desc_compare = ACTION_DESC_LITERAL(
        "vtable:compare",
        "Compare with Base",
        &ah_compare,
        nullptr,
        "Compare vtable with base class",
        -1
    );

    action_desc_t desc_funcjump = ACTION_DESC_LITERAL(
        "funcbrowser:jump",
        "Jump to Function",
        &ah_funcjump,
        nullptr,
        "Jump to selected virtual function",
        -1
    );

    action_desc_t desc_compjump_derived = ACTION_DESC_LITERAL(
        "compbrowser:jump_derived",
        "Jump to Derived Function",
        &ah_compjump_derived,
        nullptr,
        "Jump to derived class function",
        -1
    );

    action_desc_t desc_compjump_base = ACTION_DESC_LITERAL(
        "compbrowser:jump_base",
        "Jump to Base Function",
        &ah_compjump_base,
        nullptr,
        "Jump to base class function",
        -1
    );

    action_desc_t desc_comptoggle = ACTION_DESC_LITERAL(
        "compbrowser:toggle",
        "Toggle Inherited Functions",
        &ah_comptoggle,
        nullptr,
        "Toggle display of inherited functions",
        -1
    );

    action_desc_t desc_browse_funcs = ACTION_DESC_LITERAL(
        "vtable:browse_funcs",
        "Browse Functions",
        &ah_browse_funcs,
        nullptr,
        "Browse virtual functions in selected vtable",
        -1
    );

    action_desc_t desc_annotate_all = ACTION_DESC_LITERAL(
        "vtable:annotate_all",
        "Annotate All VTables",
        &ah_annotate_all,
        nullptr,
        "Annotate all vtables with function indices",
        -1
    );

    register_action(desc_explorer);
    register_action(desc_tree);
    register_action(desc_compare);
    register_action(desc_browse_funcs);
    register_action(desc_annotate_all);
    register_action(desc_funcjump);
    register_action(desc_compjump_derived);
    register_action(desc_compjump_base);
    register_action(desc_comptoggle);

    hook_event_listener(HT_UI, &ui_listener, nullptr, 0);

    return new vtable_plugin_ctx_t;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    PLUGIN_DESCRIPTION,
    "https://github.com/K4ryuu/IDA-VTableExplorer",
    "VTableExplorer",
    nullptr
};
