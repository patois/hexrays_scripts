import os

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_kernwin
import ida_diskio
from datetime import datetime

# Screen (widget) recorder for IDA Pro
__author__ = "patois"

HOTKEY = "Ctrl-Shift-R"

class screen_record_t(QtCore.QObject):
    def __init__(self, title, path):
        QtCore.QObject.__init__(self)
        self.target = ida_kernwin.PluginForm.FormToPyQtWidget(ida_kernwin.find_widget(title)).viewport()
        self.target.installEventFilter(self)
        self.painting = False
        self.title = title
        self.path = path

    def eventFilter(self, receiver, event):
        if not self.painting and \
           self.target == receiver and \
           event.type() == QtCore.QEvent.Paint:

            # Send a paint event that we won't intercept
            self.painting = True
            try:
                pev = QtGui.QPaintEvent(self.target.rect())
                QtWidgets.QApplication.instance().sendEvent(self.target, pev)
                self.pm = QtGui.QPixmap(self.target.size())
                self.target.render(self.pm)
            finally:
                self.painting = False

            try:
                filename = "%s_%s" % (self.title, datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S_%f"))
                dst = "%s.png" % (os.path.join(self.path, filename))
                print("Saving %s" % dst)
                self.pm.save(dst, "PNG")
            except:
                print("[!] Error saving file")
        return QtCore.QObject.eventFilter(self, receiver, event)

def sr_main():
    global sr

    if sr:
        del sr
        sr = None
        print("Stopped recording")
    else:
        w = ida_kernwin.get_current_widget()
        title = "IDA View-A"
        if w:
            title = ida_kernwin.get_widget_title(w)
        title = ida_kernwin.ask_str(title, 0, "Please specify title of widget to capture")
        if title:
            path = ida_kernwin.ask_str("", ida_kernwin.HIST_DIR, "Please specify destination path")
            if path and os.path.exists(path):
                sr = screen_record_t(title, path)
                print("Started recording")

try:
    sr
    ida_kernwin.info("Already installed. Press %s to start/stop recording." % HOTKEY)
except:
    sr = None
    sr_hotkey = ida_kernwin.add_hotkey(HOTKEY, sr_main)  
    print("Press %s to start/stop recording" % HOTKEY)