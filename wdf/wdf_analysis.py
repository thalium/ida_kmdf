import os

import Wdf as Wdf

if __name__ == "__main__":
    import idc

    ok = Wdf.load_wdf()
    if not ok:
        idc.qexit(1)

    ok = Wdf.apply_wdf()
    if not ok:
        idc.qexit(1)

    idc.qexit(0)
