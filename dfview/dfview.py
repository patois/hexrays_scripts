"""
This script is based on the vds12 example of the Hexrays SDK,
and has been turned into an interactive context viewer.
The script displays def/use lists of variables and highlights
them in the disassembly view.

author: de
"""

import ida_pro
import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_lines

DEBUG = False
LOG_WARNINGS = True
DECOMP_USE_CACHE = False

MC_USEDEF = 3
MC_DEF = 1
MC_USE = 2

# ----------------------------------------------------------------------------
def log_warning(s):
    if LOG_WARNINGS:
        print("[W]: %s" % s)
    return

# ----------------------------------------------------------------------------
def collect_block_xrefs(out, mlist, blk, ins, find_uses):
    p = ins
    while p and not mlist.empty():
        use = blk.build_use_list(p, ida_hexrays.MUST_ACCESS); # things used by the insn
        _def = blk.build_def_list(p, ida_hexrays.MUST_ACCESS); # things defined by the insn
        plst = use if find_uses else _def
        if mlist.has_common(plst):
            if not p.ea in out:
                out.append(p.ea) # this microinstruction seems to use our operand
        mlist.sub(_def)
        p = p.next if find_uses else p.prev

# ----------------------------------------------------------------------------
def collect_xrefs(out, ctx, mop, mlist, du, find_uses):
    # first collect the references in the current block
    start = ctx.topins.next if find_uses else ctx.topins.prev
    collect_block_xrefs(out, mlist, ctx.blk, start, find_uses)

    # then find references in other blocks
    serial = ctx.blk.serial; # block number of the operand
    bc = du[serial]          # chains of that block
    voff = ida_hexrays.voff_t(mop)
    ch = bc.get_chain(voff)   # chain of the operand
    if not ch:
        return # odd
    for bn in ch:
        b = ctx.mba.get_mblock(bn)
        ins = b.head if find_uses else b.tail
        tmp = ida_hexrays.mlist_t()
        tmp.add(mlist)
        collect_block_xrefs(out, tmp, b, ins, find_uses)

# ----------------------------------------------------------------------------
def get_xrefs(ea):
    result = None
    pfn = ida_funcs.get_func(ea)
    if pfn:
        F = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(F):
            gco = ida_hexrays.gco_info_t()
            if ida_hexrays.get_current_operand(gco):
                # generate microcode
                decomp_flags = ida_hexrays.DECOMP_NO_WAIT
                if not DECOMP_USE_CACHE:
                    decomp_flags |= ida_hexrays.DECOMP_NO_CACHE
                if DEBUG:
                    decomp_flags |= ida_hexrays.DECOMP_WARNINGS
                hf = ida_hexrays.hexrays_failure_t()
                mbr = ida_hexrays.mba_ranges_t(pfn)
                mba = ida_hexrays.gen_microcode(
                    mbr,
                    hf,
                    None,
                    decomp_flags,
                    ida_hexrays.MMAT_PREOPTIMIZED)
                if mba:
                    merr = mba.build_graph()
                    if merr == ida_hexrays.MERR_OK:
                        ncalls = mba.analyze_calls(ida_hexrays.ACFL_GUESS)
                        if ncalls < 0:
                            print("%08x: failed to determine some calling conventions", pfn.start_ea)
                        mlist = ida_hexrays.mlist_t()
                        if gco.append_to_list(mlist, mba):
                            print("mlist: %s" % mlist._print())
                            ctx = ida_hexrays.op_parent_info_t()
                            mop = mba.find_mop(ctx, ea, gco.is_def(), mlist)
                            if mop:
                                xrefs = ida_pro.eavec_t()
                                ndefs = 0
                                graph = mba.get_graph()
                                ud = graph.get_ud(ida_hexrays.GC_REGS_AND_STKVARS)
                                du = graph.get_du(ida_hexrays.GC_REGS_AND_STKVARS)                             
                                if gco.is_use():
                                    collect_xrefs(xrefs, ctx, mop, mlist, ud, False)
                                    ndefs = xrefs.size()
                                    if ea not in xrefs:
                                        xrefs.append(ea)

                                if gco.is_def():
                                    if ea not in xrefs:
                                        xrefs.append(ea)
                                        ndefs = len(xrefs)
                                    collect_xrefs(xrefs, ctx, mop, mlist, du, True)
                                result = (ea, gco, xrefs, ndefs)
                            else:
                                log_warning("Could not find the operand in the microcode, sorry")
                        else:
                            log_warning("Failed to represent %s as microcode list" % gco.name)
                    else:
                        log_warning("%08x: %s" % (hf.errea, ida_hexrays.get_merror_desc(merr, mba)))
                else:
                    log_warning("%08x: %s" % (hf.errea, hf.str))
            else:
                log_warning("Could not find a register or stkvar in the current operand")
        else:
            log_warning("Please position the cursor on an instruction")
    else:
        log_warning("Please position the cursor within a function")
    return result

# ----------------------------------------------------------------------------
class df_info_t():
    def __init__(self, type_id, ea, insn):
        self.type_id = type_id
        self.ea = ea
        self.insn = insn
        self.color = {
            MC_USEDEF:ida_kernwin.CK_EXTRA4,
            MC_DEF:ida_kernwin.CK_EXTRA3,
            MC_USE:ida_kernwin.CK_EXTRA2
        }[type_id]

# ----------------------------------------------------------------------------
class xref_chooser_t(ida_kernwin.Choose):

    class view_hooks_t(ida_kernwin.View_Hooks):
        def __init__(self, v):
            self.v = v
            ida_kernwin.View_Hooks.__init__(self)

        def view_curpos(self, widget):
            # we can safely skip this callback if
            # the cursor isn't placed on an operand
            if ida_kernwin.get_opnum() != -1:
                wt = ida_kernwin.get_widget_type(widget)
                if wt == ida_kernwin.BWN_DISASM:
                    uie = ida_kernwin.input_event_t()
                    if ida_kernwin.get_user_input_event(uie):
                        if uie.kind == ida_kernwin.iek_mouse_button_press:
                            ea = ida_kernwin.get_screen_ea()
                            result = get_xrefs(ea)#self.v.do_xrefs(ea)
                            if result:
                                ea, gco, xrefs, ndefs = result
                                self.v.update(ea, gco, xrefs, ndefs)
                            else:
                                self.v.clear()
                            ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)
            return

    class ui_hooks_t(ida_kernwin.UI_Hooks):
        def __init__(self, v):
            self.v = v
            ida_kernwin.UI_Hooks.__init__(self)

        def get_lines_rendering_info(self, out, widget, rin):
            if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
                for section_lines in rin.sections_lines:
                    for line in section_lines:
                        line_ea = line.at.toea()
                        for dfi in self.v.data:
                            if dfi.ea == line_ea:
                                e = ida_kernwin.line_rendering_output_entry_t(line)
                                e.bg_color = dfi.color
                                out.entries.push_back(e)
            
            #elif ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            #    pass

    def __init__(self):
        self.view_hooks = None
        self.ui_hooks = None
        self._init(list(), 0, None, None)
        ida_kernwin.Choose.__init__(
            self,
            "Dataflow Context Viewer",
            [["Type", 6], ["Address", 16], ["Instruction", 60]])

    def _init(self, xrefs, n, ea, gco):
        self.xrefs = xrefs
        self.ndefs = n
        self.curr_ea = ea
        self.gco = gco
        self.data = [ self._make_dfi(idx) for idx in range(len(xrefs)) ]
        self.items = [ self._make_item(dfi) for dfi in self.data ]
        if self._check_uninit_var():
            print("%x: found 'use' without 'def': potentially unititalized variable!" % ea)

    def update(self, ea, gco, xrefs, ndefs):
        self._init(xrefs, ndefs, ea, gco)
        self.Refresh()

    def clear(self):
        self.data = list()
        self.items = list([])
        self.Refresh()
        return

    def _check_uninit_var(self):
        has_use = False
        has_def = False
        for dfi in self.data:
            has_use |= dfi.type_id in [MC_USE, MC_USEDEF]
            has_def |= dfi.type_id in [MC_DEF, MC_USEDEF]
        return has_use and not has_def

    def _make_dfi(self, idx):
        ea = self.xrefs[idx]
        both_mask = ida_hexrays.GCO_USE|ida_hexrays.GCO_DEF
        both = (self.gco.flags & both_mask) == both_mask
        if ea == self.curr_ea and both:
            type_id = MC_USEDEF
        elif idx < self.ndefs:
            type_id = MC_DEF
        else:
            type_id = MC_USE
        insn = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
        return df_info_t(type_id, ea, insn)      

    def _make_item(self, dfi):
        type_str = {
            MC_USEDEF:"use/def",
            MC_DEF:"def",
            MC_USE:"use"
        }[dfi.type_id]
        return [type_str, "%x" % dfi.ea, dfi.insn]

    def show(self):
        self.view_hooks = self.view_hooks_t(self)
        self.ui_hooks = self.ui_hooks_t(self)
        self.view_hooks.hook()
        self.ui_hooks.hook()
        self.Show(False)
        return

    #def OnGetLineAttr(self, n):
    #    print(self.data[n].type_id)
    #    col = [0xff0000,0x00ff00, 0x0000ff][self.data[n].type_id]
    #    return [col, 0]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.xrefs[n])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnClose(self):
        # re-running the script with a viewer still
        # opened will cause OnClose() to be called,
        # so hooks are uninstalled safely
        if self.view_hooks:
            self.view_hooks.unhook()
            self.view_hooks = None
        if self.ui_hooks:
            self.ui_hooks.unhook()
            self.ui_hooks = None

# ----------------------------------------------------------------------------
def main():
    if ida_hexrays.init_hexrays_plugin():
        xc = xref_chooser_t()
        xc.show()

# ----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
