import ida_hexrays
import ida_lines
import ida_kernwin as kw
import random
import datetime

__author__ = "https://github.com/patois"

'''I recommend against productive use -> timers are not thread-safe'''

# try messing with the following constants:

# apply effect to decompiled text with up to 'MAX_LINES_THRESHOLD' number of lines
MAX_LINES_THRESHOLD = 250
# initial effect interval
INITIAL_INTERVAL = 50
# common effect interval
COMMON_INTERVAL = 50
# colors
COLOR_MATCH_CHAR = ida_lines.SCOLOR_DREF
COLOR_NOMATCH_CHAR = ida_lines.SCOLOR_DEFAULT

class TextModifier:
    def __init__(self, n, iv, vu):
        self.count = n
        self.n = n
        self.iv = iv
        self.vu = vu
        self.is_disabled = False
        self.ref_pc = [(ida_lines.tag_remove(sl.line).lstrip(),[]) for sl in self.vu.cfunc.get_pseudocode()]
        self.timer = kw.register_timer(0, self.timer_cb)

    def shuffle_text(self):
        pc = self.vu.cfunc.get_pseudocode()

        if len(pc) > MAX_LINES_THRESHOLD or self.is_disabled:
            return

        random.seed(datetime.datetime.now())
        lines = [ida_lines.tag_remove(sl.line) for sl in pc]

        pc.clear()
        sl = kw.simpleline_t()
        try:
            for line_no in range(len(lines)):
                line = lines[line_no]
                code = line.strip()
                prefix = " " * (len(line) - len(code))
                if self.n != 1:
                    shuffled = random.sample(code, len(code))
                else:
                    shuffled = list(code)

                for char_no in range(len(shuffled)):
                    if shuffled[char_no] == self.ref_pc[line_no][0][char_no]:
                        self.ref_pc[line_no][1].append(char_no)

                if self.n != self.count:
                    for char_no in self.ref_pc[line_no][1]:
                        shuffled[char_no] = ida_lines.COLSTR(self.ref_pc[line_no][0][char_no], COLOR_MATCH_CHAR)

                sl.line = prefix + ida_lines.COLSTR("".join(shuffled), COLOR_NOMATCH_CHAR)
                pc.push_back(sl)
        except:
            pass
        return

    def set_disabled(self, disabled):
        self.is_disabled = disabled
        kw.unregister_timer(self.timer)

    def get_cur_interval(self):
        cur_iv = -1

        # initial inverval
        if self.n == self.count:
            cur_iv = INITIAL_INTERVAL
        # common
        elif self.n == 1:
            cur_iv = COMMON_INTERVAL
        else:
            cur_iv = self.iv if self.n else -1
        return cur_iv

    def timer_cb(self):
        if self.is_disabled:
            return -1
        try:
            self.vu.refresh_view(False)
        except:
            pass
        cur_iv = self.get_cur_interval()
        self.n -= 1
        return cur_iv

class shuffle_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.t = None

    def text_ready(self, vu):
        if not self.t:
            self.t = TextModifier(20, 1, vu)
        else:
            if self.t.n:
                self.t.shuffle_text()
            else:
                self.t = None
        return 0

    def switch_pseudocode(self, vu):
        if self.t:
            self.t.set_disabled(True)
            self.t = None
        return 0

    def close_pseudocode(self, vu):
        if self.t:
            self.t.set_disabled(True)
            self.t = None
        return 0

if ida_hexrays.init_hexrays_plugin():
    try:
        shuffle
        shuffle.unhook()
        print("shuffle: removing hook")
        del shuffle
    except:
        shuffle = shuffle_t()
        shuffle.hook()
        print("shuffle: hook installed")
else:
    print("shuffle: hexrays unavailable.")
