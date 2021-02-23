import webbrowser
import ida_kernwin, ida_name, ida_funcs, ida_hexrays

__author__ = "https://github.com/patois"


def _get_identifier():
    """helper function"""
    
    r = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
    if r:
        return r[0]
    return None

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

def google_item():
    """gets textual representation of currently selected identifier
    from any current IDA view, opens a new browser tab and googles for it
    """

    name = _get_identifier()
    if name:
        webbrowser.open("http://google.com/search?q=%s" % name, new=2)
    
ida_kernwin.add_hotkey("Ctrl-Shift-F", google_item)
ida_kernwin.add_hotkey("Ctrl-Shift-N", rename_func)
print("arachno: hotkeys installed.")
