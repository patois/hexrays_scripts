from idaapi import *

__author__ = "https://github.com/patois"

def find_expr(ea, expr, parents=False):
    class expr_finder_t(ctree_visitor_t):
        def __init__(self, cfunc, expr, parents):
            ctree_visitor_t.__init__(self,
                CV_PARENTS if parents else CV_FAST)
            self.cfunc = cfunc
            self.expr = expr
            self.found = []
            return

        def visit_expr(self, e):
            cfunc = self.cfunc
            if eval(self.expr, globals(), locals()):
                self.found.append(e)
            return 0

    try:
        cfunc = decompile(ea)
    except:
        print("%x: unable to decompile." % ea)
        return []

    expr = expr.replace("\n", "")
    ef = expr_finder_t(cfunc, expr, parents)
    ef.apply_to_exprs(cfunc.body, None)
    return ef.found