from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_kernwin

# IDA Coffee
__author__ = "patois"

# -------------------------------------------------------------------------
class timercallback_t(object):
    def __init__(self, target, max):
        self.interval = 10
        self.max = max
        self.angle = 0
        self.target = target
        self.forward = True
        self.obj = ida_kernwin.register_timer(self.interval, self)
        if self.obj is None:
            raise RuntimeError("Failed to register timer")

    def get_angle(self):
        return self.angle

    def __call__(self):
        if self.forward:
            self.angle += 1
            if self.angle >= self.max:
                self.forward = False
        else:
            self.angle -= 1
            if self.angle <= -self.max:
                self.forward = True
        try:
            self.target.repaint()
        except:
            return -1
        return self.interval

    def __del__(self):
        #print("Timer object disposed %s" % self)
        pass

# -------------------------------------------------------------------------
class painter_t(QtCore.QObject):
    def __init__(self):
        QtCore.QObject.__init__(self)
        name = "Coffee"
        w = ida_kernwin.find_widget("IDA View-%s" % name)
        if not w:
            w = ida_kernwin.open_disasm_window(name)
        self.target = ida_kernwin.PluginForm.FormToPyQtWidget(w).viewport()
        self.target.installEventFilter(self)
        self.painting = False
        self.transform = False
        self.pm = QtGui.QPixmap(self.target.size())
        self.timer = timercallback_t(self.target, 2)

    def die(self):
        #calling ida_kernwin.unregister_timer(self.timer)
        #doesn't unregister the timer but setting its interval to -1 does. wtf?
        self.timer.interval = -1
        ida_kernwin.unregister_timer(self.timer)

    def eventFilter(self, receiver, event):
        if not self.painting and \
           self.target == receiver and \
           event.type() == QtCore.QEvent.Paint:

            if self.transform:
                painter = QtGui.QPainter(receiver)
                #painter.setRenderHints(QtGui.QPainter.Antialiasing)
                t = QtGui.QTransform()
                t.rotate(self.timer.get_angle())
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
                    pev = QtGui.QPaintEvent(self.target.rect())
                    QtWidgets.QApplication.instance().sendEvent(self.target, pev)
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

        return QtCore.QObject.eventFilter(self, receiver, event)
try:
    # closing the widget by its window handles
    # doesn't unregister the timer, but re-running
    # the script does
    coffee.die()
    del coffee
except:
    coffee = painter_t()