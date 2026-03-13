"""IDAPython wrapper for VTableExplorer JSON API.

Requires the VTableExplorer plugin (vtable64.dll) to be loaded.

Usage:
    from vtable_explorer import scan, entries, compare, hierarchy

    # List all vtables
    for vt in scan():
        print(f"{vt['class_name']} @ {vt['address']} ({vt['func_count']} funcs)")

    # Get entries for a specific vtable
    result = entries(0x140012340)
    for e in result['entries']:
        print(f"  [{e['index']}] {e['func_name']}")

    # Compare derived vs base
    cmp = compare(derived_addr, base_addr)
    for e in cmp['entries']:
        print(f"  [{e['index']}] {e['status']}: {e['derived_func_name']}")

    # Get class hierarchy
    h = hierarchy("CBaseEntity")
    print(f"Ancestors: {h['ancestors']}")
    print(f"Descendants: {h['descendants']}")
"""
import idc
import json


def scan():
    """Scan and return all vtables as a list of dicts."""
    return json.loads(idc.eval_idc("VTableExplorer_Scan()"))


def entries(addr):
    """Return vtable entries for the given vtable address."""
    return json.loads(idc.eval_idc(f"VTableExplorer_Entries({addr:#x})"))


def compare(derived_addr, base_addr):
    """Compare derived and base vtables."""
    return json.loads(
        idc.eval_idc(f"VTableExplorer_Compare({derived_addr:#x},{base_addr:#x})")
    )


def hierarchy(class_name):
    """Return hierarchy info for a class by name."""
    return json.loads(
        idc.eval_idc(f'VTableExplorer_Hierarchy("{class_name}")')
    )
