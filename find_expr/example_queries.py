from hr_toolbox import find_expr
from idaapi import *

# ----------------------------------------------------------------------------
def find_memcpy():
    """find calls to memcpy() where the 'n' argument
    is signed"""
    query = lambda cf, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'memcpy' in get_name(e.x.obj_ea) and
        len(e.a) == 3 and
        e.a[2].op is cot_var and
        cf.lvars[e.a[2].v.idx].tif.is_signed())

    return _db_exec_query(query)

# ----------------------------------------------------------------------------
def find_sprintf():
    """find calls to sprintf() where the format string
    argument contains '%s'"""
    query = lambda cfunc, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'sprintf' in get_name(e.x.obj_ea) and
        len(e.a) >= 2 and
        e.a[1].op is cot_obj and
        is_strlit(get_flags(e.a[1].obj_ea)) and
        b'%s' in get_strlit_contents(e.a[1].obj_ea, -1, 0, STRCONV_ESCAPE))

    return _db_exec_query(query)

# ----------------------------------------------------------------------------
def find_gpa():
    """find dynamically imported functions (Windows)"""
    query = lambda cfunc, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'GetProcAddress' in get_name(e.x.obj_ea) and
        len(e.a) == 2 and
        e.a[1].op is cot_obj and
        is_strlit(get_flags(e.a[1].obj_ea)))

    gpa = get_name_ea_simple('GetProcAddress')
    ea_list = [f.start_ea for f in [get_func(xref.frm) for xref in XrefsTo(gpa, XREF_FAR)] if f]
    return _exec_query(query, list(dict.fromkeys(ea_list)), lambda x:"%x: %s" % (x.ea,
            get_strlit_contents(x.a[1].obj_ea, -1, 0, STRCONV_ESCAPE).decode("utf-8")))

# ----------------------------------------------------------------------------
def _db_exec_query(query, fmt=lambda x:"%x: %s" % (x.ea, tag_remove(x.print1(None)))):
    result = []
    for ea in Functions():
        result += [fmt(e) for e in find_expr(ea, query)]
    return result

# ----------------------------------------------------------------------------
def _exec_query(query, ea_list, fmt=lambda x:"%x: %s" % (x.ea, tag_remove(x.print1(None)))):
    result = []
    for ea in ea_list:
        result += [fmt(e) for e in find_expr(ea, query)]
    return result