from PyQt5.Qt import QApplication
import webbrowser
import ida_kernwin, ida_name, ida_funcs, ida_hexrays

__author__ = "https://github.com/patois"

SCRIPT_NAME = "arachno"

def _get_identifier():
    """helper function"""
    
    r = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
    if r:
        return r[0]
    return None

def copy_to_clipboard():
    """copies current identifier to clipboard"""

    name = _get_identifier()
    if name:
        QApplication.clipboard().setText(name)
    return

def make_name():
    """renames current item

    TODO:replace with custom implementation that allows
    parameters such as name and flags ("create name anyway") to be set"""

    cv = ida_kernwin.get_current_viewer()
    if cv:
        hx = ida_kernwin.get_widget_type(cv) == ida_kernwin.BWN_PSEUDOCODE
        ida_kernwin.process_ui_action("hx:Rename" if hx else "MakeName")
    return

def rename_func():
    """gets textual representation of currently selected identifier
    from any current IDA view and suggests it as a new current
    function name
    """

    name = _get_identifier()
    if name:
        str = ida_kernwin.ask_str(name, -1, "Rename function")
        if str:
            f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
            if f:
                if ida_name.set_name(f.start_ea, str, ida_name.SN_NOCHECK):
                    cv = ida_kernwin.get_current_viewer()
                    if ida_kernwin.get_widget_type(cv) == ida_kernwin.BWN_PSEUDOCODE:
                        vd = ida_hexrays.get_widget_vdui(cv)
                        if vd:
                            vd.refresh_view(True)
    return

def google_item():
    """gets textual representation of currently selected identifier
    from any current IDA view, opens a new browser tab and googles for it
    """

    name = _get_identifier()
    if name:
        webbrowser.open("http://google.com/search?q=%s" % name, new=2)

def toggle_install():
    global INSTALLED_HOTKEYS

    activated = False

    try:
        INSTALLED_HOTKEYS
        for i in INSTALLED_HOTKEYS:
            ida_kernwin.del_hotkey(i)
        del INSTALLED_HOTKEYS
    except:
        INSTALLED_HOTKEYS = [handler for handler in [
            ida_kernwin.add_hotkey("Ctrl-Shift-C", copy_to_clipboard),
            ida_kernwin.add_hotkey("Ctrl-Shift-F", google_item),
            ida_kernwin.add_hotkey("Ctrl-Shift-N", rename_func),
            ida_kernwin.add_hotkey("Ctrl-Shift-V", make_name)]
        ]
        activated = True

    return activated

active = toggle_install()
print("%s: hotkeys %sinstalled." % (SCRIPT_NAME, "" if active else "un"))
