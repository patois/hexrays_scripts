import ida_hexrays as hr

__author__ = "https://github.com/patois"

def find_expr(ea, expr, findall=True, parents=False):
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