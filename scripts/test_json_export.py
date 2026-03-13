"""Test script for VTableExplorer JSON export IDC functions.

Run in IDA's IDAPython console (File > Script file...) or paste into the console.
Requires vtable64.dll plugin to be loaded.
"""
import idc
import json
import traceback

def test_scan():
    print("\n=== Test: VTableExplorer_Scan() ===")
    raw = idc.eval_idc("VTableExplorer_Scan()")
    if raw == 0 or raw is None:
        print("FAIL: eval_idc returned None/0 - is the plugin loaded?")
        return None
    vtables = json.loads(raw)
    print(f"OK: Found {len(vtables)} vtables")
    for vt in vtables[:5]:
        print(f"  {vt['class_name']} @ {vt['address']} "
              f"({vt['func_count']} funcs, {vt['pure_virtual_count']} pure)")
    if len(vtables) > 5:
        print(f"  ... and {len(vtables) - 5} more")

    # Validate schema on first entry
    if vtables:
        expected_keys = {
            "address", "class_name", "display_name", "func_count",
            "pure_virtual_count", "is_abstract", "base_classes",
            "derived_classes", "derived_count", "has_multiple_inheritance",
            "has_virtual_inheritance", "is_intermediate", "is_windows"
        }
        actual_keys = set(vtables[0].keys())
        missing = expected_keys - actual_keys
        extra = actual_keys - expected_keys
        if missing:
            print(f"  WARN: missing keys: {missing}")
        if extra:
            print(f"  INFO: extra keys: {extra}")
        if not missing:
            print(f"  Schema OK: all {len(expected_keys)} expected keys present")
    return vtables


def test_entries(vtables):
    print("\n=== Test: VTableExplorer_Entries(addr) ===")
    # Pick a non-intermediate vtable with functions
    target = None
    for vt in vtables:
        if not vt["is_intermediate"] and vt["func_count"] > 0:
            target = vt
            break
    if not target:
        print("SKIP: no suitable vtable found")
        return

    addr = target["address"]
    raw = idc.eval_idc(f"VTableExplorer_Entries({addr})")
    result = json.loads(raw)

    if "error" in result:
        print(f"FAIL: {result['error']}")
        return

    entries = result["entries"]
    print(f"OK: {target['class_name']} @ {addr} -> {len(entries)} entries")
    for e in entries[:5]:
        pv = " [pure]" if e["is_pure_virtual"] else ""
        print(f"  [{e['index']}] {e['func_name'] or '(unnamed)'} @ {e['func_addr']}{pv}")
    if len(entries) > 5:
        print(f"  ... and {len(entries) - 5} more")
    return target


def test_compare(vtables):
    print("\n=== Test: VTableExplorer_Compare(derived, base) ===")
    # Find a vtable with a base class that also has a vtable
    derived = None
    base_addr = None
    for vt in vtables:
        if vt["is_intermediate"] or not vt["base_classes"]:
            continue
        base_name = vt["base_classes"][0]
        for other in vtables:
            if other["class_name"] == base_name and not other["is_intermediate"]:
                derived = vt
                base_addr = other["address"]
                break
        if derived:
            break
    if not derived:
        print("SKIP: no derived/base pair found")
        return

    raw = idc.eval_idc(
        f"VTableExplorer_Compare({derived['address']},{base_addr})"
    )
    result = json.loads(raw)
    print(f"OK: {result['derived_class']} vs {result['base_class']}")
    print(f"  Inherited: {result['inherited_count']}, "
          f"Overridden: {result['overridden_count']}, "
          f"New: {result['new_virtual_count']}")
    for e in result["entries"][:3]:
        print(f"  [{e['index']}] {e['status']}: {e['derived_func_name'] or '?'}")
    if len(result["entries"]) > 3:
        print(f"  ... and {len(result['entries']) - 3} more")


def test_hierarchy(vtables):
    print("\n=== Test: VTableExplorer_Hierarchy(class_name) ===")
    # Pick a class that has both ancestors and descendants if possible
    target = None
    for vt in vtables:
        if vt["base_classes"] and vt["derived_classes"]:
            target = vt
            break
    if not target:
        # Fall back to any class with base classes
        for vt in vtables:
            if vt["base_classes"]:
                target = vt
                break
    if not target and vtables:
        target = vtables[0]
    if not target:
        print("SKIP: no vtables")
        return

    name = target["class_name"]
    raw = idc.eval_idc(f'VTableExplorer_Hierarchy("{name}")')
    result = json.loads(raw)

    if "error" in result:
        print(f"FAIL: {result['error']}")
        return

    print(f"OK: {result['class_name']} @ {result['address']}")
    print(f"  Ancestors:   {result['ancestors']}")
    print(f"  Descendants: {result['descendants']}")
    print(f"  Funcs: {result['func_count']}, Abstract: {result['is_abstract']}")


def test_error_handling():
    print("\n=== Test: Error handling ===")
    # Entries for nonexistent address
    raw = idc.eval_idc("VTableExplorer_Entries(0xDEADBEEF)")
    result = json.loads(raw)
    if "error" in result:
        print(f"OK: bad address -> {result['error']}")
    else:
        print(f"WARN: no error for bad address (got {len(result.get('entries', []))} entries)")

    # Hierarchy for nonexistent class
    raw = idc.eval_idc('VTableExplorer_Hierarchy("NonExistentClass12345")')
    result = json.loads(raw)
    if "error" in result:
        print(f"OK: bad class -> {result['error']}")
    else:
        print(f"WARN: no error for bad class name")


def main():
    print("=" * 60)
    print("VTableExplorer JSON Export - Test Suite")
    print("=" * 60)

    try:
        vtables = test_scan()
        if vtables is None:
            print("\nABORT: Scan failed, cannot continue")
            return

        if vtables:
            test_entries(vtables)
            test_compare(vtables)
            test_hierarchy(vtables)
        else:
            print("\nNo vtables found in this binary (expected for non-C++ binaries)")

        test_error_handling()

        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)
    except Exception as e:
        print(f"\nERROR: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
