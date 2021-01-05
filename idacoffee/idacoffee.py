from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_kernwin

# IDA Coffee
__author__ = "patois"

HOTKEY = "Ctrl-Shift-C"

# -------------------------------------------------------------------------
class painter_t(QtCore.QObject):
    def __init__(self):
        QtCore.QObject.__init__(self)
        name = "Coffee"
        w = ida_kernwin.find_widget("IDA View-%s" % name)
        if not w:
            w = ida_kernwin.get_current_widget()
            if not w:
                name = "Coffee"
                w = ida_kernwin.open_disasm_window("IDA View-%s" % name)
        self.painting = False
        self.transform = False
        self.target = ida_kernwin.PluginForm.FormToPyQtWidget(w).viewport()
        self.pm = QtGui.QPixmap(self.target.size())

        self.target.installEventFilter(self)
        self.timer = self.timercallback_t(self.target, 2)

    class timercallback_t(object):
        def __init__(self, target, max_val):
            self.interval = 10
            self.max_val = max_val
            self.target = target
            self.lane = [i for i in range(-max_val, max_val+1)] + [i for i in range(max_val-1, -max_val, -1)]
            self.n = len(self.lane)
            self.i = 0
            self.obj = ida_kernwin.register_timer(self.interval, self)
            if self.obj is None:
                raise RuntimeError("Failed to register timer")

        def get_val(self):
            return self.lane[self.i]

        def die(self):
            ida_kernwin.unregister_timer(self.obj)

        def __call__(self):
            self.i = (self.i + 1) % self.n
            try:
                self.target.repaint()
            except:
                return -1
            return self.interval

    def die(self):
        self.timer.die()
        self.target.removeEventFilter(self)

    def eventFilter(self, receiver, event):
        if not self.painting and \
           self.target == receiver and \
           event.type() == QtCore.QEvent.Paint:

            if self.transform:
                painter = QtGui.QPainter(receiver)
                #painter.setRenderHints(QtGui.QPainter.Antialiasing)
                t = QtGui.QTransform()
                t.rotate(self.timer.get_val())
                pixmap_rotated = self.pm.transformed(t)
                painter.drawPixmap(self.target.rect(), pixmap_rotated)
                painter.end()

                self.transform = False
                # prevent the widget form painting itself again
                return True

            else:
                # Send a paint event that we won't intercept
                self.painting = True
                try:
                    self.pm = QtGui.QPixmap(self.target.size())
                    # render widget to pixmap, side-effect: repaints widget :(
                    self.target.render(self.pm)
                finally:
                    self.painting = False
                    self.transform = True
                    """workaround!
                    widget.render() causes widget to be repainted.
                    In order to deal with this situation, we'll issue
                    another repaint() and transform the widget"""
                    self.target.repaint()
        elif event.type() in [QtCore.QEvent.Close, QtCore.QEvent.Hide]:
            self.die()

        return QtCore.QObject.eventFilter(self, receiver, event)

def coffee_main():
    global coffee

    if coffee:
        coffee.die()
        del coffee
        coffee = None
    else:
        coffee = painter_t()
        ida_kernwin.msg("Caffeinated\n")

try:
    coffee
    ida_kernwin.info("Already installed. Press %s to start/stop recording." % HOTKEY)
except:
    coffee = None
    print("Press %s for coffee overload" % HOTKEY)
    ida_kernwin.add_hotkey(HOTKEY, coffee_main)