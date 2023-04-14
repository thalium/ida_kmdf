import idaapi
import idc
import wdf as wdf


class WdfPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Detect wdf version and apply associated wdf types"
    wanted_name = "Wdfalyzer"
    wanted_hotkey = "Alt-F11"

    def init(self):
        self.run()

    def run(self):
        if wdf.load_wdf():
            wdf.apply_wdf()
            idaapi.auto_wait()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return WdfPlugin()
