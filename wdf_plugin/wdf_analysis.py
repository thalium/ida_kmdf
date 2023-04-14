import os

import wdf as wdf

if __name__ == "__main__":
    import idc

    ok = wdf.load_wdf()
    if not ok:
        idc.qexit(1)

    ok = wdf.apply_wdf()
    if not ok:
        idc.qexit(1)

    idc.qexit(0)
