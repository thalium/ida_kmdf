import inspect
import os
import subprocess
import sys

if "IDA_DIR" not in os.environ.keys():
    print("fatal: missing IDA_DIR environment variable")
    sys.exit(1)

ida_dir = os.path.abspath(os.environ["IDA_DIR"])
ida_plugins_dir = os.path.abspath(os.path.join(ida_dir, "plugins"))
idat = "idat64.exe" if os.name == "nt" else "idat64"
idat_filepath = os.path.join(ida_dir, idat)

file_path = inspect.getsourcefile(lambda: 0)
root_dir = os.path.dirname(os.path.abspath(file_path))


def usage():
    print(
        f"Usage: \tpython {sys.argv[0]} analyze <file(s)> ... -> analyze WDF driver\
            \n\tpython {sys.argv[0]} make_til [--wdf=<wdf_dir>] [--wdk=<wdk_dir>] [--til=<til_dir>] [--no_casts] -> create .til files for WDF"
    )


def run_script(script: str):
    files = sys.argv[2:]

    if len(files) == 0:
        usage()
        return

    run_script = os.path.abspath(os.path.join(root_dir, "utils", "run_ida_script.py"))
    ida_script = os.path.abspath(os.path.join(root_dir, "wdf_plugin", script))

    for file in files:
        args = [sys.executable, run_script, file, ida_script]
        try:
            subprocess.check_call(args)
        except subprocess.CalledProcessError:
            print(f"Wdf analysis failed for {file}")
            sys.exit(1)
        print()


def analyze():
    run_script("wdf_analysis.py")


def make_til():

    file = file_path  # We do not need a real binary, so let's use this script

    if os.path.exists("til_creator_output.txt"):
        os.remove("til_creator_output.txt")

    til_creator = os.path.abspath(
        os.path.abspath(os.path.join(root_dir, "wdf_til_creation", "wdf_til_creator.py"))
    )
    script = f'"{til_creator}"'

    for arg in sys.argv[2:]:
        script += f' "{arg}"'

    idat_args = [idat_filepath, "-A", "-Ltil_creator_output.txt", f"-S{script}", file]

    try:
        subprocess.check_call(idat_args)
    except subprocess.CalledProcessError:
        print("Failed to create WDF typelibs. See til_creator_output.txt")
        sys.exit(1)

    with open("til_creator_output.txt", "r") as f:
        for line in f:
            if line.startswith("Created"):
                print(line, end="")

options = {
    "analyze": analyze,
    "make_til": make_til,
}


def main():
    try:
        options[sys.argv[1]]()
    except (IndexError, KeyError):
        usage()

    return 0


if __name__ == "__main__":
    main()
