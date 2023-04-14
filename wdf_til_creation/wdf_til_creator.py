import inspect
import os
import subprocess
import sys

import ida_loader
import idaapi
import idc

FILE_PATH = inspect.getsourcefile(lambda: 0)
ROOT_DIR = os.path.dirname(os.path.abspath(FILE_PATH))

GLOBAL_HEADER = os.path.join(ROOT_DIR, "include", "wdf_global_header.h")
PFN_HEADER = os.path.join(ROOT_DIR, "include", "generated_pfn.h")

IDA_DIR = ida_dir = idc.idadir()


def import_types_to_change(wdf_til):
    """
    This function imports locally the types we want to change.
    The import seems mandatory if we want to access and thus modify
    their declaration.
    """

    name = idaapi.first_named_type(wdf_til, idaapi.NTF_TYPE)
    while name is not None:
        if "PFN_" in name:
            idaapi.import_type(wdf_til, -1, name, idaapi.IMPTYPE_OVERRIDE)

        name = idaapi.next_named_type(wdf_til, name, idaapi.NTF_TYPE)


def create_ntstatus64(wdf_til) -> bool:
    """
    Many WDF functions return an NTSTATUS type (4 btyes).
    In 64 bit mode, IDA will mistakenly set return types to 8 bytes.
    Because of that, our prototypes won't match what IDA has infered
    and a cast will be present.

    To avoid this cast while still having the information about  the
    NTSTATUS return type, we create an NTSTATUS64 (8 byes) which will
    remove the cast.
    """

    strtype = "typedef __int64 NTSTATUS64;"
    tif = idaapi.tinfo_t()
    idaapi.parse_decl(tif, None, strtype, 0)

    ok = tif.set_named_type(wdf_til, "NTSTATUS64", idaapi.NTF_REPLACE)
    if ok != idaapi.TERR_OK:
        print("Couldn't load modified type NTSTATUS64")
        return False

    # No need to import it locally, parse_decl() uses wdf_til as a base
    return True


def get_local_types():
    """
    This is an iterator to get all local types with their tinfo and
    associated data.
    """

    idati = idaapi.get_idati()
    ord_qty = idaapi.get_ordinal_qty(idati)
    ord_qty = 0 if ord_qty == 0xFFFFFFFF else ord_qty

    for ordinal in range(1, ord_qty):
        tinfo = idaapi.tinfo_t()

        ok = tinfo.get_numbered_type(idati, ordinal)
        if not ok:
            continue

        typeof, fields = idaapi.idc_get_local_type_raw(ordinal)
        if not typeof:
            continue

        yield tinfo, typeof, fields


def fix_local_type(wdf_til, tinfo, typeof, fields, ntstatus64: bool) -> bool:
    """
    This function adds the __fastcall convention to the function
    pointers.
    The ntstatus64 bool replace the NTSTATUS return
    types by NTSTATUS64 types to keep some of the information and
    remove all casts.
    """

    name = f"{tinfo}"
    flags = idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE
    strtype = idaapi.idc_print_type(typeof, fields, name, flags)
    idati = idaapi.get_idati()

    if strtype is not None and "(*PFN_" in strtype:

        if ntstatus64:
            strtype = strtype.replace("typedef NTSTATUS", "typedef NTSTATUS64")

        strtype = strtype.replace("(*PFN_", "(__fastcall *PFN_")
        strtype = strtype.replace("\n", ";")

        next_tif = idaapi.tinfo_t()

        ok = idaapi.parse_decl(next_tif, wdf_til, strtype, 0)
        if not ok:
            print(f"Could not parse declaration {name} -> {strtype}")
            return False

        ok = next_tif.set_named_type(wdf_til, name, idaapi.NTF_REPLACE)
        if ok != idaapi.TERR_OK:
            print(f"Couldn't load modified type {name} -> {strtype}")
            return False

        # Delete local type so that it can be overwritten upon reloading the .til
        idaapi.del_named_type(idati, name, idaapi.NTF_TYPE)

    return True


def modify_til(
    til_filename: str, is_64bit: bool, avoid_ida_casts: bool, wdf_til
) -> bool:
    """
    This function will import and change the WDF function pointer types
    of a given til and overwrite the old til with the new declarations.
    """
    ntstatus64 = is_64bit and avoid_ida_casts
    if ntstatus64:
        avoid_ida_casts = create_ntstatus64(wdf_til)

    import_types_to_change(wdf_til)

    for tinfo, typeof, fields in get_local_types():
        ok = fix_local_type(wdf_til, tinfo, typeof, fields, ntstatus64)
        if not ok:
            print(f"Could not change {tinfo}.")

    # The original til will be overwritten by its new version.
    ok = idaapi.store_til(wdf_til, None, til_filename)
    return ok


def polish_til(til_filename: str, is_64bit: bool, avoid_ida_casts: bool) -> bool:
    """
    This function changes all WDF function pointer types to avoid
    IDA casts. By default, it only adds the fastcall convention.

    On 64bit, IDA might set all return values to __int64, even those
    with 32 bit return type (NTSTATUS). The optionnal argument --no_casts
    creates a fake type NTSATUS64 which will be treated as an __int64
    and apply it to the WDF function.

    This new type is factually wrong, but will avoid all casts while still
    offering the information of the NTSTATUS return type, and is meant for
    better readability during the analysis.
    """

    wdf_til = idaapi.load_til(til_filename)
    if wdf_til is None:
        print(f"Error, couldn't load til {til_filename}.")
        return False

    ok = modify_til(til_filename, is_64bit, avoid_ida_casts, wdf_til)
    if not ok:
        print(f"Error: couldn't modify til {til_filename}.")
        return False

    return True


def validate_til(til_filepath: str) -> bool:
    wdf_til = idaapi.load_til(til_filepath)
    if wdf_til is None:
        print("Error, couldn't load til")
        return False

    bind_info_present = False
    wdf_functions_present = False

    name = idaapi.first_named_type(wdf_til, idaapi.NTF_TYPE)
    while name is not None:
        if name == "WDF_BIND_INFO":
            bind_info_present = True

        elif name == "WDFFUNCTIONS":
            wdf_functions_present = True

        name = idaapi.next_named_type(wdf_til, name, idaapi.NTF_TYPE)

    return bind_info_present and wdf_functions_present


def check_missing_files(*args):
    missing = []

    for file in args:
        if not os.path.exists(file):
            missing.append(file)

    return missing


def create_til(
    til_filepath: str,
    wdf_dir: str,
    wdk_dir: str,
    version: str,
    version_dir: str,
    is_64bit: bool,
    debug: bool,
) -> bool:
    """
    Create a global header with all necessary includes, and launch tilib
    as a subprocess to create a til.
    """

    create_global_header(wdf_dir, version, version_dir)

    if is_64bit:
        tilib = "tilib64.exe" if os.name == "nt" else "tilib64"
    else:
        tilib = "tilib.exe" if os.name == "nt" else "tilib"

    tilib_path = os.path.join(IDA_DIR, tilib)

    if not os.path.exists(tilib_path):
        print(f"Error, could not find tilib binary at {tilib_path}. Is it installed?")
        return False

    wdm_til = os.path.join(IDA_DIR, "til", "pc", "wdm.til")
    fx_dir = os.path.join(
        wdf_dir, "src", "framework", "shared", "inc", "private", "common"
    )
    kmdf_dir = os.path.join(wdf_dir, "src", "framework", "kmdf", "inc", "private")
    wdf_um_dir = os.path.join(
        wdf_dir, "src", "framework", "shared", "inc", "private", "um"
    )
    wdk_shared_dir = os.path.join(wdk_dir, "shared")
    wdk_km_dir = os.path.join(wdk_dir, "km")
    wdk_um_dir = os.path.join(wdk_dir, "um")

    missing = check_missing_files(
        fx_dir, kmdf_dir, wdk_shared_dir, wdk_km_dir, wdk_um_dir, wdf_um_dir, wdm_til
    )
    if missing != []:
        print(
            "Error, some necessary include files are missing, please check your includes."
        )
        print("Missing files and directories:")
        for file in missing:
            print(file)
        return False

    tilib_args = [
        tilib_path,
        "-c",  # Create til
        f"-I{version_dir}",  # Include directories
        f"-I{fx_dir}",
        f"-I{kmdf_dir}",
        f"-I{wdk_shared_dir}",
        f"-I{wdk_km_dir}",
        f"-I{wdf_um_dir}",
        f"-I{wdk_um_dir}",
        f"-I{os.path.join(ROOT_DIR, 'include')}",
        f"-h{GLOBAL_HEADER}",  # Header to parse
        f"-b{wdm_til}",  # Base til
        "-e",  # Ignore errors
        "-R",  # Allow redeclarations
        "-Cc1",  # Visual C++ compiler
        f"{til_filepath}",  # Output file,
    ]

    try:
        if debug:
            f = open(f"wdf_{version}_debug", "w")
            subprocess.check_call(tilib_args, stdout=f)

        else:
            subprocess.check_output(
                tilib_args
            )  # I want to display output only on exceptions.

    except subprocess.CalledProcessError as err:
        print(
            f"Failed to create til for WDF version {version}\n{err.output.decode()}",
            end="",
        )
        return False

    return True


def create_global_header(wdf_dir: str, version: str, version_dir: str):
    """
    Tilib can only parse one header file at a time. This function will
    create a global header containing all the necessary includes in order
    to parse everything in one go.

    The headers wdf_base.h and generated_pfn.h are custom made with necessary
    types which are not included by the wdf headers or the base til wdm.til.
    """

    global_header = open(GLOBAL_HEADER, "w")
    global_header.write('#include "wdf_base.h"\n')
    global_header.write('#include "generated_pfn.h"\n')
    global_header.write('#include "sdkddkver.h"\n')  # Needed for wdfcore.h

    wdf_headers = os.path.join(version_dir)
    files = sorted(os.listdir(wdf_headers))
    for f in files:
        if f.endswith(".h"):
            global_header.write(f'#include "{f}"\n')

    global_header.write('#include "fxldr.h"\n')  # For the WdfVersionBind prototype

    um_headers = os.path.join(
        wdf_dir, "src", "framework", "shared", "inc", "private", "um"
    )
    files = sorted(os.listdir(um_headers))
    for f in files:
        if f.endswith(".h") and f != "fxldrum.h":
            global_header.write(f'#include "{f}"\n')

    fx_headers = os.path.join(wdf_dir, "src", "framework", "kmdf", "inc", "private")
    files = sorted(os.listdir(fx_headers))
    for f in files:
        if (
            f.startswith("fx")
            and f.endswith(".h")
            or f == f"wdf{version.replace('.', '')}.h"
        ):
            global_header.write(f'#include "{f}"\n')


def create_pfn_header(wdf_dir: str) -> bool:
    """
    This function will parse all PFN types in fxdynamics.h
    and put them in a header with a bsic type. Since there are
    several wdf versions but only one fxdynamics.h for all,
    having a base with all PFN typedefs will avoid incompatibilities
    and unknown types during the .til creation.
    """

    pfn_header = open(PFN_HEADER, "w")
    fxdynamics_header = os.path.join(
        wdf_dir, "src", "framework", "kmdf", "inc", "private", "fxdynamics.h"
    )
    if not os.path.exists(fxdynamics_header):
        print(f"Error: missing necessary header {fxdynamics_header}")
        return False

    with open(fxdynamics_header, "r") as f:
        for line in f:
            split = line.split()

            # This simple heuristics will get the all the PFN types
            # used in the WDFFUNCTIONS struct
            if len(split) == 2 and split[1].startswith("pfnWdf"):
                pfn_header.write(f"typedef int (*{split[0]})(void);\n")

    return True


def make_til(
    version,
    version_dir,
    wdf_dir,
    wdk_dir,
    is_64bit,
    til_dir,
    avoid_ida_casts,
    debug=False,
) -> bool:
    if is_64bit:
        til_filename = f"wdf64-{version.replace('.', '-')}.til"
    else:
        til_filename = f"wdf-{version.replace('.', '-')}.til"

    til_filepath = os.path.join(til_dir, til_filename)
    arch = "64 bit" if is_64bit else "32 bit"

    ok = create_til(
        til_filepath,
        wdf_dir,
        wdk_dir,
        version,
        os.path.join(version_dir, version),
        is_64bit,
        debug,
    )
    if not ok:
        print(f"Could not create {arch} til for version {version}")
        return False

    print(f"Created {arch} til for version {version}")

    ok = validate_til(til_filepath)
    if not ok:
        print(
            f"Typelib is incomplete for {arch} version {version}.\nPerhaps some include files are missing.\nYou can try debug mode to have more logs."
        )
        return False
    polish_til(til_filepath, is_64bit, avoid_ida_casts)
    return True


def try_make_til(
    version,
    version_dir,
    wdf_dir,
    wdk_dir,
    is_64bit,
    til_dir,
    avoid_ida_casts,
    debug=False,
) -> bool:
    max_tries = 1 if idaapi.IDA_SDK_VERSION >= 750 else 16

    # IDA 7.4 and lower have memory bugs in their sdk which can throw exceptions during
    # the til creations. Those are rare but possible, so we try several times to make the
    # til before giving up.
    for i in range(max_tries):
        try:
            return make_til(
                version,
                version_dir,
                wdf_dir,
                wdk_dir,
                is_64bit,
                til_dir,
                avoid_ida_casts,
                debug,
            )
        except UnicodeDecodeError:
            continue

    print(f"Failed to create .til for verion {version} after {max_tries} tries")
    return False


def create_wdf_tils(
    wdf_dir: str,
    wdk_dir: str,
    til_dir: str = ROOT_DIR,
    avoid_ida_casts: bool = False,
) -> int:
    """
    This is the entry when used from IDA's GUI.
    It will create two .til for each version (32-bit and 64-bit).
    """

    ok = create_pfn_header(wdf_dir)
    if not ok:
        return 1

    nb_errors = 0
    version_dir = os.path.join(wdf_dir, "src", "publicinc", "wdf", "kmdf")

    for version in os.listdir(version_dir):
        for is_64bit in [False, True]:
            ok = try_make_til(
                version,
                version_dir,
                wdf_dir,
                wdk_dir,
                is_64bit,
                til_dir,
                avoid_ida_casts,
            )
            if not ok:
                nb_errors += 1

    return nb_errors


def main():
    """
    This script will parse the WDF sources in order to generate a .til for each
    version of it.

    The .til will then be polished for a better usage with IDA (__fastcall
    conventions will be added to function pointers for example).

    This is the entry from the command line script.
    """

    wdf_dir = os.path.join(ROOT_DIR, "dev", "WDF")
    wdk_dir = os.path.join(ROOT_DIR, "dev", "WDK")
    til_dir = os.path.abspath(os.path.join(ROOT_DIR, "..", "wdf_til"))

    try:
        os.mkdir(til_dir, 0o666)
    except FileExistsError:
        pass
    
    avoid_ida_casts = False
    debug = False
    for arg in idc.ARGV:
        if arg.startswith("--wdf"):
            wdf_dir = os.path.abspath(arg.split("=")[-1])
            if not os.path.exists(wdf_dir):
                print("\n\nInvalid path for WDF files\n\n")
                idc.qexit(1)
        elif arg.startswith("--wdk"):
            wdk_dir = os.path.abspath(arg.split("=")[-1])
            if not os.path.exists(wdk_dir):
                print("\n\nInvalid path for WDK headers\n\n")
                idc.qexit(1)
        elif arg.startswith("--til"):
            til_dir = os.path.abspath(arg.split("=")[-1])
            if not os.path.exists(til_dir):
                os.mkdir(til_dir, 0o666)
        elif arg == "--no_casts":
            avoid_ida_casts = True
        elif arg == "--debug":
            debug = True

    ok = create_pfn_header(wdf_dir)
    if not ok:
        idc.qexit(1)

    nb_errors = 0
    version_dir = os.path.join(wdf_dir, "src", "publicinc", "wdf", "kmdf")

    for version in os.listdir(version_dir):
        for is_64bit in [False, True]:
            ok = try_make_til(
                version,
                version_dir,
                wdf_dir,
                wdk_dir,
                is_64bit,
                til_dir,
                avoid_ida_casts,
                debug,
            )
            if not ok:
                nb_errors += 1

    ida_loader.set_database_flag(ida_loader.DBFL_KILL)  # Do not save database
    idc.qexit(nb_errors)


if __name__ == "__main__":
    main()
