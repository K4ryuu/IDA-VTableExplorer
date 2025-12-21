#pragma once
#include <ida.hpp>
#include <graph.hpp>
#include <kernwin.hpp>
#include <moves.hpp>
#include <map>
#include <set>
#include <string>
#include "rtti_parser.h"
#include "vtable_comparison.h"
#include "vtable_utils.h"

namespace inheritance_graph {

struct graph_data_t {
    std::map<int, std::string> node_labels;
    std::map<int, ea_t> node_vtables;
    std::map<int, uint32> node_colors;
    std::map<int, std::vector<int>> edges;  // node -> children
    int node_count = 0;
    std::string current_class;
    int current_node = -1;

    int add_node(const std::string& label, ea_t vtable_addr, uint32 bg_color) {
        int node = node_count++;
        node_labels[node] = label;
        node_vtables[node] = vtable_addr;
        node_colors[node] = bg_color;
        edges[node] = std::vector<int>();
        return node;
    }

    void add_edge(int from, int to) {
        edges[from].push_back(to);
    }

    ea_t get_vtable(int node) const {
        auto it = node_vtables.find(node);
        return it != node_vtables.end() ? it->second : BADADDR;
    }
};

inline void collect_ancestors(
    const std::string& cls,
    const std::map<std::string, const VTableInfo*>& vtable_map,
    std::set<std::string>& lineage)
{
    auto it = vtable_map.find(cls);
    if (it == vtable_map.end()) return;

    const VTableInfo* vt = it->second;

    if (vt->is_intermediate && !vt->parent_class.empty()) {
        if (lineage.insert(vt->parent_class).second)
            collect_ancestors(vt->parent_class, vtable_map, lineage);
        return;
    }

    for (const auto& base : vt->base_classes) {
        if (lineage.insert(base).second)
            collect_ancestors(base, vtable_map, lineage);
    }
}

inline void collect_descendants(
    const std::string& cls,
    const std::vector<VTableInfo>* all_vtables,
    std::set<std::string>& lineage)
{
    for (const auto& vt : *all_vtables) {
        for (const auto& base : vt.base_classes) {
            if (base == cls && lineage.insert(vt.class_name).second) {
                collect_descendants(vt.class_name, all_vtables, lineage);
                break;
            }
        }
    }
}


static ssize_t idaapi graph_callback(void *ud, int code, va_list va) {
    graph_data_t *data = (graph_data_t *)ud;

    switch (code) {
        case grcode_user_refresh: return 1;

        case grcode_clicked: {
            va_arg(va, graph_viewer_t *);
            selection_item_t *item = va_arg(va, selection_item_t *);
            if (item && item->is_node) {
                ea_t addr = data->get_vtable(item->node);
                if (addr != BADADDR) jumpto(addr);
            }
            return 0;
        }

        case grcode_dblclicked: {
            graph_viewer_t *gv = va_arg(va, graph_viewer_t *);
            selection_item_t *item = va_arg(va, selection_item_t *);
            if (item && item->is_node) viewer_center_on(gv, item->node);
            return 0;
        }

        case grcode_destroyed:
            delete data;
            return 0;

        default: break;
    }
    return 0;
}


inline void calc_stats(ea_t child, ea_t parent, bool is_win,
                       const std::vector<ea_t>& sorted,
                       int& inherited, int& overridden, int& new_funcs)
{
    inherited = overridden = new_funcs = 0;
    if (child == BADADDR || parent == BADADDR) return;

    auto cmp = vtable_comparison::compare_vtables(child, parent, is_win, sorted);
    inherited = cmp.inherited_count;
    overridden = cmp.overridden_count;
    new_funcs = cmp.new_virtual_count;
}

inline void pad_line(char* out, int sz, const char* lbl, const char* val, int w) {
    int pad = w - 4 - strlen(lbl) - strlen(val);
    if (pad < 1) pad = 1;

    char* p = out;
    p += qsnprintf(p, sz, "  %s", lbl);
    for (int i = 0; i < pad && (p - out) < sz - 3; i++) *p++ = ' ';
    qsnprintf(p, sz - (p - out), "%s  ", val);
}

inline void show_inheritance_graph(
    const std::string& class_name,
    ea_t vtable_addr,
    bool is_windows,
    const std::vector<VTableInfo>* all_vtables)
{
    TWidget* existing = find_widget("Inheritance Lineage");
    if (existing) {
        close_widget(existing, WCLS_DONT_SAVE_SIZE);
    }

    if (!all_vtables || all_vtables->empty()) {
        warning("No vtables available");
        return;
    }

    show_wait_box("Building lineage...");

    std::map<std::string, const VTableInfo*> vtable_map;
    std::vector<ea_t> sorted_vtables;
    sorted_vtables.reserve(all_vtables->size());
    for (const auto& vt : *all_vtables) {
        vtable_map[vt.class_name] = &vt;
        sorted_vtables.push_back(vt.address);
    }
    std::sort(sorted_vtables.begin(), sorted_vtables.end());

    std::set<std::string> lineage;
    lineage.insert(class_name);  // Add selected class

    size_t before_ancestors = lineage.size();
    collect_ancestors(class_name, vtable_map, lineage);  // Add all parents up to root
    size_t ancestors_count = lineage.size() - before_ancestors;

    size_t before_descendants = lineage.size();
    collect_descendants(class_name, all_vtables, lineage);  // Add all children down
    size_t descendants_count = lineage.size() - before_descendants;

    graph_data_t *data = new graph_data_t();
    std::map<std::string, int> class_to_node;

    using namespace vtable_utils;
    const uint32 NORMAL_COLOR = GRAPH_NORMAL;     // Medium-dark tan (good contrast)
    const uint32 SELECTED_COLOR = GRAPH_SELECTED; // Lighter tan for selection highlight
    const uint32 ABSTRACT_COLOR = GRAPH_ABSTRACT; // Medium purple (good contrast)

    for (const std::string& cls : lineage) {
        auto it = vtable_map.find(cls);

        bool found = (it != vtable_map.end());
        const VTableInfo* vt = found ? it->second : nullptr;
        bool is_intermediate = found ? vt->is_intermediate : true;

        char label[1024];
        char lines[10][256];
        int line_count = 0;
        bool is_abstract = (found && !is_intermediate) ? (vt->pure_virtual_count > 0) : false;

        // Intermediate node
        if (!found || is_intermediate) {
            bool is_selected = (cls == class_name);
            if (is_selected) {
                qsnprintf(lines[line_count++], 256, "  %s (SELECTED)  ", cls.c_str());
            } else {
                qsnprintf(lines[line_count++], 256, "  %s  ", cls.c_str());
            }

            int name_len = strlen(lines[0]);
            const int LINE_WIDTH = (name_len > 50) ? name_len : 50;
            if (name_len < LINE_WIDTH) {
                for (int i = name_len; i < LINE_WIDTH && i < 255; i++) {
                    lines[0][i] = ' ';
                }
                lines[0][LINE_WIDTH] = '\0';
            }

            int sep_idx = 0;
            lines[line_count][sep_idx++] = ' ';
            lines[line_count][sep_idx++] = ' ';
            for (int i = 2; i < LINE_WIDTH - 2 && sep_idx < 255; i++) {
                lines[line_count][sep_idx++] = '-';
            }
            lines[line_count][sep_idx++] = ' ';
            lines[line_count][sep_idx++] = ' ';
            lines[line_count][sep_idx] = '\0';
            line_count++;

            if (found && vt->parent_vtable_addr != BADADDR) {
                char parent_ref[64];
                qsnprintf(parent_ref, sizeof(parent_ref), "uses %s", vt->parent_class.c_str());
                pad_line(lines[line_count++], 256, "VTable  :", parent_ref, LINE_WIDTH);
            } else {
                pad_line(lines[line_count++], 256, "VTable  :", "(none)", LINE_WIDTH);
            }
            pad_line(lines[line_count++], 256, "Type    :", "Inlined by compiler", LINE_WIDTH);

            label[0] = '\0';
            for (int i = 0; i < line_count; i++) {
                if (i > 0) qstrncat(label, "\n", sizeof(label) - strlen(label) - 1);
                qstrncat(label, lines[i], sizeof(label) - strlen(label) - 1);
            }

            uint32 color = is_selected ? SELECTED_COLOR : 0x808080;
            ea_t node_addr = (found && vt->parent_vtable_addr != BADADDR) ? vt->parent_vtable_addr : BADADDR;
            int node = data->add_node(label, node_addr, color);
            class_to_node[cls] = node;
            continue;
        }

        bool is_selected = (cls == class_name);
        if (is_selected && is_abstract) {
            qsnprintf(lines[line_count++], 256, "  %s [abstract] (SELECTED)  ", cls.c_str());
        } else if (is_selected) {
            qsnprintf(lines[line_count++], 256, "  %s (SELECTED)  ", cls.c_str());
        } else if (is_abstract) {
            qsnprintf(lines[line_count++], 256, "  %s [abstract]  ", cls.c_str());
        } else {
            qsnprintf(lines[line_count++], 256, "  %s  ", cls.c_str());
        }

        int name_len = strlen(lines[0]);
        const int LINE_WIDTH = (name_len > 50) ? name_len : 50;

        if (name_len < LINE_WIDTH) {
            for (int i = name_len; i < LINE_WIDTH && i < 255; i++) {
                lines[0][i] = ' ';
            }
            lines[0][LINE_WIDTH] = '\0';
        }

        int sep_idx = 0;
        lines[line_count][sep_idx++] = ' ';
        lines[line_count][sep_idx++] = ' ';
        for (int i = 2; i < LINE_WIDTH - 2 && sep_idx < 255; i++) {
            lines[line_count][sep_idx++] = '-';
        }
        lines[line_count][sep_idx++] = ' ';
        lines[line_count][sep_idx++] = ' ';
        lines[line_count][sep_idx] = '\0';
        line_count++;

        char addr_val[32];
        qsnprintf(addr_val, sizeof(addr_val), "0x%llX", (unsigned long long)vt->address);
        pad_line(lines[line_count++], 256, "Addr    :", addr_val, LINE_WIDTH);

        char funcs_val[32];
        if (is_abstract) {
            qsnprintf(funcs_val, sizeof(funcs_val), "%d (%d pure)", vt->func_count, vt->pure_virtual_count);
        } else {
            qsnprintf(funcs_val, sizeof(funcs_val), "%d", vt->func_count);
        }
        pad_line(lines[line_count++], 256, "Funcs   :", funcs_val, LINE_WIDTH);

        char parent_val[128];
        ea_t parent_vtable_addr = BADADDR;
        std::string stats_parent_name;
        if (!vt->base_classes.empty()) {
            const char* parent_name = vt->base_classes[0].c_str();
            if (vt->base_classes.size() > 1) {
                qsnprintf(parent_val, sizeof(parent_val), "%s (+%d)", parent_name, (int)vt->base_classes.size() - 1);
            } else {
                qsnprintf(parent_val, sizeof(parent_val), "%s", parent_name);
            }
            for (const auto& base : vt->base_classes) {
                auto parent_it = vtable_map.find(base);
                if (parent_it != vtable_map.end() && !parent_it->second->is_intermediate) {
                    parent_vtable_addr = parent_it->second->address;
                    stats_parent_name = base;
                    break;
                }
            }
        } else {
            qsnprintf(parent_val, sizeof(parent_val), "(root)");
        }
        pad_line(lines[line_count++], 256, "Parent  :", parent_val, LINE_WIDTH);

        char kids_val[16];
        qsnprintf(kids_val, sizeof(kids_val), "%d", vt->derived_count);
        pad_line(lines[line_count++], 256, "Children:", kids_val, LINE_WIDTH);

        if (parent_vtable_addr != BADADDR) {
            int inherited = 0, overridden = 0, new_funcs = 0;
            calc_stats(vt->address, parent_vtable_addr, vt->is_windows, sorted_vtables, inherited, overridden, new_funcs);

            char inh_val[16], ovr_val[16], new_val[16];
            qsnprintf(inh_val, sizeof(inh_val), "%d", inherited);
            qsnprintf(ovr_val, sizeof(ovr_val), "%d", overridden);
            qsnprintf(new_val, sizeof(new_val), "%d", new_funcs);

            pad_line(lines[line_count++], 256, "Inherit :", inh_val, LINE_WIDTH);
            pad_line(lines[line_count++], 256, "Override:", ovr_val, LINE_WIDTH);
            pad_line(lines[line_count++], 256, "New     :", new_val, LINE_WIDTH);
        }

        label[0] = '\0';
        for (int i = 0; i < line_count; i++) {
            if (i > 0) qstrncat(label, "\n", sizeof(label) - strlen(label) - 1);
            qstrncat(label, lines[i], sizeof(label) - strlen(label) - 1);
        }

        uint32 color = (cls == class_name) ? SELECTED_COLOR : is_abstract ? ABSTRACT_COLOR : NORMAL_COLOR;

        int node = data->add_node(label, vt->address, color);
        class_to_node[cls] = node;
    }

    // Edges
    for (const std::string& cls : lineage) {
        auto it = vtable_map.find(cls);
        int child_node = class_to_node[cls];

        if (it == vtable_map.end()) {
            for (const auto& [other_cls, other_vt] : vtable_map) {
                for (size_t i = 0; i < other_vt->base_classes.size(); ++i) {
                    if (other_vt->base_classes[i] == cls) {
                        if (i + 1 < other_vt->base_classes.size()) {
                            const std::string& parent = other_vt->base_classes[i + 1];
                            auto parent_it = class_to_node.find(parent);
                            if (parent_it != class_to_node.end()) {
                                data->add_edge(parent_it->second, child_node);
                            }
                        }
                        goto next_class;
                    }
                }
            }
            next_class:
            continue;
        }

        // Intermediate: use parent_class field
        if (it->second->is_intermediate && !it->second->parent_class.empty()) {
            auto parent_it = class_to_node.find(it->second->parent_class);
            if (parent_it != class_to_node.end()) {
                data->add_edge(parent_it->second, child_node);
            }
            continue;
        }

        if (!it->second->base_classes.empty()) {
            const std::string& direct_parent = it->second->base_classes[0];
            auto parent_it = class_to_node.find(direct_parent);
            if (parent_it != class_to_node.end()) {
                data->add_edge(parent_it->second, child_node);
            }
        }
    }

    interactive_graph_t* graph = create_interactive_graph(10000 + rand());

    for (int i = 0; i < data->node_count; i++)
        graph->resize(i + 1);

    for (int i = 0; i < data->node_count; i++) {
        node_info_t ni;
        ni.text = data->node_labels[i].c_str();
        ni.ea = data->node_vtables[i];
        ni.bg_color = data->node_colors[i];
        set_node_info(graph->gid, i, ni, NIF_TEXT | NIF_BG_COLOR | NIF_EA);
    }

    for (const auto& [from, tos] : data->edges) {
        for (int to : tos) {
            edge_info_t ei;
            graph->add_edge(from, to, &ei);
        }
    }

    graph_viewer_t* viewer = create_graph_viewer("Inheritance Lineage", graph->gid, graph_callback, data, 0);
    set_viewer_graph(viewer, graph);
    graph->del_custom_layout();
    graph->create_digraph_layout();

    display_widget(viewer, WOPN_DP_TAB | WOPN_PERSIST);
    refresh_viewer(viewer);

    int selected_node = class_to_node[class_name];
    viewer_center_on(viewer, selected_node);

    graph_location_info_t gli;
    gli.zoom = 1.0;
    viewer_set_gli(viewer, &gli, 0);

    refresh_viewer(viewer);

    hide_wait_box();
}

} // namespace inheritance_graph
