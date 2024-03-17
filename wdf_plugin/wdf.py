import os

import ida_bytes
import ida_funcs
import ida_nalt
import ida_struct
import ida_typeinf
import idaapi
import idautils
import idc

LOG_ERROR = "error"
LOG_WARN = "warn"
LOG_INFO = "info"
LOG_DEBUG = "debug"


def log(message: str, file=None, level=LOG_INFO, callee=LOG_DEBUG):
    log = f"[KMDF][{level}] {message}\n"
    if callee:
        import inspect

        try:
            callee = inspect.stack()[1][3]
        except BaseException:
            callee = "unk"

        log = f"[KMDF][{level}][{callee}] {message}\n"

    if file:  # or level != LOG_INFO:
        if not file:
            file = level + ".txt"

        filepath = os.path.join(LOG_PATH, file)
        with open(filepath, "a+") as fh:
            fh.write(f"{message}\n")

    if file is None:
        idaapi.msg(log)


def apply_driver_globals() -> bool:
    names = idautils.Names()

    version_bind_ea = None
    for (ea, name) in names:
        if "WdfVersionBind" in name and "Class" not in name:
            version_bind_ea = ea
            break

    if version_bind_ea is None:
        return False

    args_addrs = None
    for xref in idautils.XrefsTo(version_bind_ea):
        # There could be several xrefs, not all in section .text,
        # and not all being a call. So we iterate to get a call.
        frm = xref.frm
        args_addrs = idaapi.get_arg_addrs(frm)
        if args_addrs is not None:
            break

    if args_addrs is None:
        return False

    if len(args_addrs) != 4:
        return False

    insn = idautils.DecodeInstruction(
        args_addrs[3]
    )  # DriverGlobals is the 4th argument
    driver_globals = None
    for op in insn.ops:
        # I need to check both values and addr because IDA uses either one
        # in 32 bit or 64 bit
        if op.addr != 0:  # Registers and direct values don't have addresses
            driver_globals = op.addr
        elif op.value != 0:  # Registers and direct values don't have values
            driver_globals = op.value
            break

    if driver_globals is None:
        return False

    ok = idc.set_name(driver_globals, "WdfDriverGlobals", flags=idc.SN_NOCHECK|idc.SN_NON_WEAK)
    if not ok:
        # We need to unset a type because it seems to be wrong...
        to_unset = ida_bytes.prev_head(driver_globals, 0)
        ida_bytes.del_items(to_unset, 0, 1, None)
        idc.set_name(driver_globals, "WdfDriverGlobals", flags=idc.SN_NOCHECK|idc.SN_NON_WEAK)

    ok = ida_typeinf.apply_cdecl(None, driver_globals, "PWDF_DRIVER_GLOBALS;", ida_typeinf.TINFO_DEFINITE)
    if not ok:
        idaapi.warning("Failed to apply PWDF_DRIVERGLOBALS type")
        return False



    return True


def apply_wdffunctions_stroffs(tid, reg, ea):
    func = ida_funcs.get_func(ea)
    for ea in idautils.Heads(ea, func.end_ea):
        insn = idautils.DecodeInstruction(ea)
        for op in insn.ops:
            # This is a simple heuristic, we want an instruction of the for
            # mov reg, [reg + offset], so the instruction must have either
            # an operand of type phrase or displacement
            if op.type in [idaapi.o_phrase, idaapi.o_displ] and op.reg == reg:
                idaapi.op_stroff(insn, 1, tid, 1, 0)
                # For now, we stop at the first one in case the register changes
                # We do not want to mistype something
                # TODO: check if register changes and stop then?
                return


def apply_function_xrefs(wdf_functions_ea, wdffunctions_tid):
    tid = idaapi.tid_array(1)
    tid[0] = wdffunctions_tid
    xrefs = idautils.XrefsTo(wdf_functions_ea)
    for xref in xrefs:
        frm = xref.frm
        insn = idautils.DecodeInstruction(frm)
        if insn.Op1.type == idaapi.o_reg:
            # We want loading instruction, to the first operand
            # ought to be a register
            reg = insn.Op1.reg
            # tid.cast because op_stroff used in this function
            # wants a pointer
            apply_wdffunctions_stroffs(tid.cast(), reg, frm)


def apply_wdf_functions() -> bool:
    struc = None

    # Since ida 8.4, the _WDF_BIND_INFO structure is not imported automatically so we have to import it manually
    ida_typeinf.import_type(None, -1, "_WDF_BIND_INFO", ida_typeinf.IMPTYPE_OVERRIDE)
    tid = ida_typeinf.import_type(None, -1, "WDFFUNCTIONS", ida_typeinf.IMPTYPE_OVERRIDE)
    for idx, sid, name in idautils.Structs():

        if "_WDF_BIND_INFO" in name:
            struc = ida_struct.get_struc(sid)
            xrefs = idautils.XrefsTo(sid)

            if xrefs is []:
                log(
                    "Failed to find xrefs to BIND_INFO struc",
                    level=LOG_ERROR,
                )
                idaapi.warning("Failed to find xrefs to BIND_INFO struc")
                return False

            # Find the offset of FuncTable
            members = idautils.StructMembers(sid)
            for soff, member_name, size in members:
                if member_name == "FuncTable":
                    offset = soff
                    break

            for xref in xrefs:
                ptr = idaapi.get_qword(xref.frm + offset)
                ok = idc.set_name(ptr, "WdfFunctions", flags=idc.SN_NOCHECK|idc.SN_NON_WEAK)
                if not ok:
                    # We need to unset a type because it seems to be wrong...
                    to_unset = ida_bytes.prev_head(ptr, 0)
                    ida_bytes.del_items(to_unset, 0, 1, None)
                    idc.set_name(ptr, "WdfFunctions", flags=idc.SN_NOCHECK|idc.SN_NON_WEAK)

                ok = ida_typeinf.apply_cdecl(None, ptr, "WDFFUNCTIONS *;", ida_typeinf.TINFO_DEFINITE)
                if not ok:
                    idaapi.warning("Failed to apply WDFFUNCTIONS * type")
                    # Continue because there might be other references, even though
                    # this would be surprising
                    continue
                apply_function_xrefs(ptr, tid)

    if struc is None:
        log("Failed to find BIND_INFO struc", level=LOG_ERROR)
        idaapi.warning("Failed to find BIND_INFO struc")
        return False

    return True


def apply_wdf() -> bool:
    """
    Find the _WDF_BIND_INFO structure and set the WDFFUNCTIONS * type
    to replace all offsets with the proper WDF function and propagate the
    argument types.
    """

    ok = apply_driver_globals()
    if ok:
        apply_wdf_functions()

    return True


def find_wdf_version_via_str() -> str:
    """
    Tries to locate the customary utf-16le string 'KmdfLibrary'
    in the global WDF_bind_info structure and getting the
    next two dwords, which will be the major and the minor.
    """

    ea = ida_bytes.bin_search(
        0,
        0xFFFFFFFFFFFFFFFF,
        "KmdfLibrary".encode("utf-16le"),
        None,
        ida_bytes.BIN_SEARCH_FORWARD,
        ida_bytes.BIN_SEARCH_NOSHOW,
    )
    if ea == idaapi.BADADDR:
        return None, None

    xrefs = list(idautils.XrefsTo(ea))
    if xrefs is []:
        return None, None

    for xref in xrefs:
        ptr_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
        major = idaapi.get_dword(xref.frm + ptr_size)
        minor = idaapi.get_dword(xref.frm + ptr_size + 4)
        bind_info = xref.frm - ptr_size
        break  # There should be only one ref in WDF_BIND_INFO

    return f"{major}-{minor}", bind_info


def get_version_from_call(frm) -> str:
    """
    Receives an adress containing a call to WdfVersinoBind
    and tries to get the third argument to locate the
    WDF_BIND_INFO structure and get the version via
    its offset.
    """
    args_addrs = idaapi.get_arg_addrs(frm)

    if len(args_addrs) != 4:
        return None, None

    insn = idautils.DecodeInstruction(args_addrs[2])  # BindInfo is the 3rd argument
    bind_info = None
    for op in insn.ops:
        if op.addr != 0:  # Registers and direct values don't have addresses
            bind_info = op.addr
            break

    if bind_info is None:
        return None, None

    ptr_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
    major = idaapi.get_dword(bind_info + ptr_size * 2)
    minor = idaapi.get_dword(bind_info + ptr_size * 2 + 4)

    return f"{major}-{minor}", bind_info


def find_wdf_version_via_version_bind() -> str:
    """
    Tries to locate a call to WdfVersionBind to get the
    global structure WDF_BIND_INFO (third argument) and
    get the version via the proper offset.
    """
    names = idautils.Names()

    version_bind_ea = None
    for (ea, name) in names:
        if "WdfVersionBind" in name and "Class" not in name:
            version_bind_ea = ea
            break

    if version_bind_ea is None:
        return None, None

    ok = ida_typeinf.apply_cdecl(
        None,
        version_bind_ea,
        "int WdfVersionBind(int, int, int, int);",  # Set type to allow argument recuperation
        ida_typeinf.TINFO_DEFINITE
    )
    if not ok:
        idaapi.warning("Could not change WdfVersionBind type to get its arguments")
        return None, None

    idaapi.auto_wait()  # Wait for the type propagation
    version = None

    for xref in idautils.XrefsTo(version_bind_ea):
        frm = xref.frm
        version, bind_info = get_version_from_call(frm)
        if version is not None:
            break

    idc.SetType(version_bind_ea, "")  # Remove our fake type
    return version, bind_info


def find_wdf_version():
    """
    Tries to find the WDF version used via two ways.

    First, locate a WdfVersionBind call and use the
    WDF_BIND_INFO global to get it via its offset.

    Second, if the first failed, find the customary string
    'KmdfLibrary' also located in the WDF_BIND_INFO global
    and find the version via the proper offset.
    """
    version, bind_info = find_wdf_version_via_version_bind()

    if version is None:
        version, bind_info = find_wdf_version_via_str()

    return version, bind_info


def load_wdf(til_dir=os.path.join(idc.idadir(), "til")) -> bool:
    """
    Find the version of WDF and load the associated .til if it exists.
    """

    wdf_version, bind_info_ea = find_wdf_version()
    if wdf_version is None:
        log("Could not find WDF version. Is this a WDF driver?", level=LOG_INFO)
        return False

    if idaapi.get_inf_structure().is_64bit():
        til_path = os.path.join(til_dir, f"wdf64-{wdf_version}.til")
    else:
        til_path = os.path.join(til_dir, f"wdf-{wdf_version}.til")

    ok = ida_typeinf.add_til(til_path, ida_typeinf.ADDTIL_DEFAULT)
    if ok != ida_typeinf.ADDTIL_OK:

        log("Failed to load WDF til", level=LOG_ERROR)
        return False

    # We need to wait for IDA to parse the prototype of WdfBindVersion and apply
    # the WDF_BIND_INFO struct type.
    idaapi.auto_wait()

    ok = idc.set_name(bind_info_ea, "BindInfo", flags=idc.SN_NOCHECK|idc.SN_NON_WEAK)
    if not ok:
        # We need to unset a type because it seems to be wrong...
        to_unset = ida_bytes.prev_head(bind_info_ea, 0)
        ida_bytes.del_items(to_unset, 0, 1, None)
        idc.set_name(bind_info_ea, "BindInfo", flags=idc.SN_NOCHECK|idc.SN_NON_WEAK)

    ok = ida_typeinf.apply_cdecl(None, bind_info_ea, "struct _WDF_BIND_INFO;", ida_typeinf.TINFO_DEFINITE)
    if not ok:
        idaapi.warning("Failed to apply WDF_BIND_INFO type")
    # Set bind info type in force to be sure the plugin will work

    log("WDF til successfully loaded", level=LOG_INFO)
    return True
