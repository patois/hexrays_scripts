from PyQt5.Qt import QApplication
import webbrowser
import ida_kernwin, ida_name, ida_funcs, ida_hexrays
from ida_idaapi import BADADDR

__author__ = "https://github.com/patois"

SCRIPT_NAME = "arachno"

def _get_identifier():
    """helper function"""
    
    r = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
    return r[0] if r else None

def copy_item_to_clipboard():
    """copy current identifier to clipboard"""

    name = _get_identifier()
    if name:
        print("[%s]: copied item to clipboard:'%s'" % (SCRIPT_NAME, name))
        QApplication.clipboard().setText(name)
    return

def copy_ea_to_clipboard():
    """copy current effective address to clipboard"""

    fmt = "%x" % ida_kernwin.get_screen_ea()
    QApplication.clipboard().setText(fmt)
    print("[%s]: copied ea to clipboard: '%s'" % (SCRIPT_NAME, fmt))
    return

def make_name():
    """rename current item"""

    """TODO:replace with custom implementation that allows
    parameters such as name and flags ("create name anyway") to be set
    """

    cv = ida_kernwin.get_current_viewer()
    if cv:
        hx = ida_kernwin.get_widget_type(cv) == ida_kernwin.BWN_PSEUDOCODE
        name = QApplication.clipboard().text()
        if hx and len(name):
            vd = ida_hexrays.get_widget_vdui(cv)
            if vd.get_current_item(ida_hexrays.USE_KEYBOARD):
                e = vd.item.e if vd.item.is_citem() else None
                ea = ida_kernwin.get_screen_ea()
                if e:
                    if e.op is ida_hexrays.cot_var:
                        var = vd.cfunc.mba.vars[e.v.idx]
                        old_name = var.name
                        eff_name = ida_kernwin.ask_str(name, 0, "new name for %s? " % old_name)
                        if eff_name and vd.rename_lvar(var, eff_name, True):
                            print("renamed: \"%s\" -> \"%s\"" % (old_name, name))
                        return
                    elif e.op is ida_hexrays.cot_obj:
                        ea = e.obj_ea
                    else:
                        ea = e.ea
                if ea != BADADDR:
                    old_name = ida_name.get_name(ea)
                    if old_name:
                        eff_name = ida_kernwin.ask_str(name, 0, "new name for %s? " % old_name)
                        if ida_name.set_name(ea, eff_name):
                            print("renamed: \"%s\" -> \"%s\"" % (old_name, name))
                        return
        ida_kernwin.process_ui_action("hx:Rename" if hx else "MakeName")
    return

def rename_func(do_refresh=True):
    """rename function, suggests current identifier as function name"""

    name = _get_identifier()
    if name:
        _str = ida_kernwin.ask_str(name, -1, "Rename function")
        if _str:
            f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
            if f:
                if ida_name.set_name(f.start_ea, _str, ida_name.SN_NOCHECK):
                    print("renamed: %x -> \"%s\"" % (f.start_ea, _str))
                    if do_refresh:
                        cv = ida_kernwin.get_current_viewer()
                        if ida_kernwin.get_widget_type(cv) == ida_kernwin.BWN_PSEUDOCODE:
                            vd = ida_hexrays.get_widget_vdui(cv)
                            if vd:
                                vd.refresh_view(True)
    return

def google_item():
    """google for currently selected identifier"""

    name = _get_identifier()
    if name:
        webbrowser.open("http://google.com/search?q=%s" % name, new=2)

def print_help():
    """print this help"""
    global INSTALLED_HOTKEYS

    s = list()
    for _, item in INSTALLED_HOTKEYS.items():
        hotkey, func = item
        s.append("%s:\t%s" % (hotkey, func.__doc__.replace("\n", " ")))
    print("\n%s %s help %s\n%s" % (40*"-", SCRIPT_NAME, 40*"-", "\n".join(s)))
    return

def navhistory_prev():
    """jump to previous navigation history location"""
    ida_kernwin.process_ui_action("Return")

def navhistory_next():
    """jump to next navigation history location"""
    ida_kernwin.process_ui_action("UndoReturn")

def func_prev():
    """jump to previous function"""
    ida_kernwin.process_ui_action("JumpPrevFunc")

def func_next():
    """jump to next functionm"""
    ida_kernwin.process_ui_action("JumpNextFunc")

def install_hotkey(item):
    global INSTALLED_HOTKEYS

    hotkey, func = item
    handler = ida_kernwin.add_hotkey(hotkey, func)
    if handler:
        INSTALLED_HOTKEYS[handler] = (hotkey, func)
    return handler != None

def install_hotkeys():
    global INSTALLED_HOTKEYS

    INSTALLED_HOTKEYS = {}
    items = [("Ctrl-Shift-C", copy_item_to_clipboard),
    ("Ctrl-Shift-F", google_item),
    ("Ctrl-Shift-N", rename_func),
    ("Ctrl-Shift-V", make_name),
    ("Ctrl-Shift-E", copy_ea_to_clipboard),
    ("Ctrl-Shift-H", print_help),
    ("Alt-Left", navhistory_prev),
    ("Alt-Right", navhistory_next),
    ("Ctrl-Alt-Up", func_prev),
    ("Ctrl-Alt-Down", func_next)]
    for item in items:
        if not install_hotkey(item):
            print("[%s]: failed installing hotkey %s" % (SCRIPT_NAME, item[0]))
    return

def remove_hotkeys():
    global INSTALLED_HOTKEYS

    for i in INSTALLED_HOTKEYS:
        ida_kernwin.del_hotkey(i)
    del INSTALLED_HOTKEYS
    return

def toggle_install():
    global INSTALLED_HOTKEYS

    activated = False

    try:
        INSTALLED_HOTKEYS
        remove_hotkeys()
    except:
        install_hotkeys()
        activated = True

    return activated

if __name__ == "__main__":
    active = toggle_install()
    msg = "[%s]: hotkeys %sinstalled%s." % (
        SCRIPT_NAME,
        "" if active else "un",
        " (press Ctrl-Shift-H for a list of hotkeys)" if active else "")
    print("%s" % msg)
