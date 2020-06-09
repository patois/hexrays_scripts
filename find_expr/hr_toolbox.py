import ida_hexrays as hr
import ida_bytes, idautils, ida_kernwin, ida_lines

__author__ = "https://github.com/patois"

# ----------------------------------------------------------------------------
def find_expr(ea, expr, findall=True, parents=False):
    """find expr within AST of decompiled function"""

    class expr_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, expr, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.findall = findall
            self.cfunc = cfunc
            self.expr = expr
            self.found = []
            return

        def visit_expr(self, e):
            cfunc = self.cfunc
            if self.expr(cfunc, e):
                self.found.append(e)
                if not self.findall:
                    return 1
            return 0

    try:
        cfunc = hr.decompile(ea)
    except:
        print("%x: unable to decompile." % ea)
        return []

    ef = expr_finder_t(cfunc, expr, parents)
    ef.apply_to_exprs(cfunc.body, None)
    return ef.found

# ----------------------------------------------------------------------------
def db_exec_query(query):
    """run query on all functions in current db

    returns list of cexpr_t
    """

    result = []
    for ea in idautils.Functions():
        result += [e for e in find_expr(ea, query)]
    return result

# ----------------------------------------------------------------------------
def exec_query(query, ea_list):
    """run query on list of addresses

    returns list of cexpr_t
    """

    result = []
    for ea in ea_list:
        result += [e for e in find_expr(ea, query)]
    return result

# ----------------------------------------------------------------------------
def query_db(query,
        fmt=lambda x:"%x: %s" % (x.ea,
            ida_lines.tag_remove(x.print1(None)))):
    """run query on idb, print results"""

    r = db_exec_query(query)
    try:
        for e in r:
            print(fmt(e))
    except:
        print("<query_db> error!")
    return

# ----------------------------------------------------------------------------
def query(query,
        ea_list=None,
        fmt=lambda x:"%x: %s" % (x.ea,
            ida_lines.tag_remove(x.print1(None)))):
    """run query on list of addresses, print results"""

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]

    r = exec_query(query, ea_list)
    try:
        for e in r:
            print(fmt(e))
    except:
        print("<query> error!")
    return

# ----------------------------------------------------------------------------
def display(f,
        fmt=lambda x:"%x: %s" % (x.ea,
            ida_lines.tag_remove(x.print1(None)))):
    """execute function f and print results according to fmt.

    f is expected to return a list of cexpr_t objects
    """

    try:
        for e in f():
            print(fmt(e))
    except Exception as exc:
        print("<display> error!:", exc)
    return

# ----------------------------------------------------------------------------
def display_argstr(f, idx):
    """execute function f and print results.
    
    idx is an index into the argument list of a cexpr_t 
    """

    try:
        display(f, lambda x:"%x: %s" % (x.ea,
            ida_bytes.get_strlit_contents(x.a[idx].obj_ea, -1, 0,
                ida_bytes.STRCONV_ESCAPE).decode("utf-8")))
    except Exception as exc:
        print("<display_argstr> error!:", exc)
    return