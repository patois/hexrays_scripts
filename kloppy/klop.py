from idaapi import *

__KLOPPY__ = r"""
  __
 /  \
 +  +    It looks like you're inspecting
 @  @    '%s', which is a %s variable.
 |  ||   
 || ||   It is defined at 0x%x.
 |\_/|
 \___/
"""
class kloppy_t(Hexrays_Hooks):
    def __init__(self):
        Hexrays_Hooks.__init__(self)

    def _get_vtype(self, var):
        if not var:
            return "unknown"
        if var.is_stk_var():
            return "stack"
        if var.is_reg_var():
            return "reg"
        return "unknown"

    def create_hint(self, vd):
        cmts = []
        if vd:
            i = vd.get_current_item(USE_MOUSE)
            if i and vd.item.citype == VDI_EXPR:
                if vd.item.e.op == cot_var:
                    lvars = vd.cfunc.get_lvars()
                    if lvars:
                        var = lvars[vd.item.e.v.idx]
                        if var:
                            cmts.append(__KLOPPY__ % (var.name, self._get_vtype(var), var.defea))                          
                            if var.is_stk_var():
                                offs = var.get_stkoff()
                                frsize = get_frame_lvar_size(vd.cfunc.entry_ea)
                                frregs = get_frame_regs_size(vd.cfunc.entry_ea)
                                cmts.append("Shh! It can hold ~%d bytes until\n"
                                "it hits the end of the frame!" % (frsize + frregs - offs))
                            if var.is_arg_var:
                                cmts.append("Shh! This is a function argument variable!")
                            if var.is_result_var:
                                cmts.append("Shh! This is a result variable!")

                            cmts.append(8 * "-")
                            cmts.append("")
                            custom_hint = "\n".join(cmts)
                            return (2, custom_hint, len(cmts))
        return 0
try:
    kloppy.unhook()
    print("kloppy disappears :(")
    del kloppy
except:
    kloppy = kloppy_t()
    kloppy.hook()
    print("kloppy is here!")