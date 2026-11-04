# Python plugins run in your own interpreter with the `paranoia` module and the IDAPython-style
# names (idc, idautils, ...). Paranoia asks before the first run of each version.
import idautils, idc


def count_unnamed():
    total = 0
    for ea in idautils.Functions():
        if idc.get_func_name(ea).startswith("sub_"):
            total += 1
    print(total, "unnamed functions")
