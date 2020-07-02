import webbrowser
import ida_kernwin as kw

__author__ = "https://github.com/patois"

def arachno():
	"""gets textual representation of currently selected identifier
	from any current IDA view, opens a new browser tab and googles for it
	"""

    r = kw.get_highlight(kw.get_current_viewer())
    if r:
        webbrowser.open("http://google.com/search?q=%s" % r[0],new=2)
    
kw.add_hotkey("Ctrl-Shift-F", arachno)