import argparse
import inspect
import logging
import os
import platform
import random
import shutil
import string
import subprocess
import sys
import tempfile


def log(line):
    sys.stderr.write(line + "\n")


class Ctx:
    def __init__(self):
        if "IDA_DIR" not in os.environ.keys():
            errx(self, "missing IDA_DIR environment variable")

        self.ida_dir = os.path.abspath(os.environ["IDA_DIR"].strip('"\''))
        # log(f"* IDA_DIR:\t{self.ida_dir}")
        suffix = ".exe" if sys.platform == "win32" else ""
        self.ida32 = os.path.join(self.ida_dir, "idat" + suffix)
        self.ida64 = os.path.join(self.ida_dir, "idat64" + suffix)
        # log(f"* idat32:\t{self.ida32}")
        log(f"* idat64:\t{self.ida64}")


def errx(ctx, *args):
    args = "".join(args)
    log(f"error: {args}")
    sys.exit(-1)


def get_script_exec_args(ctx, input_file, database, script, script_args: [str]):
    """ Craft IDA command line to run script """
    _, input_filename = os.path.split(input_file)
    input_filename = input_filename.split(".")[0]
    fd, logfile = tempfile.mkstemp(prefix=f"{input_filename}_", suffix=".log")
    os.close(fd)
    os.remove(logfile)
    ctx.logfile = logfile
    log(f"* log:\t{ctx.logfile}")
    q = '\\"'
    quoted_args = ""
    if len(script_args):
        quoted_args = " " + q + (q + " " + q).join(script_args) + q
    return f'"{ctx.ida}" -A -L"{logfile}" -S"{q}{script}{q}{quoted_args}" "{database}"'


def run_ida_batchmode(ctx, filepath: str) -> bool:
    """ Use ida64 to create an IDB from a file """
    args = f'"{ctx.ida64}" -B "{filepath}"'
    is_windows = platform.system() == "Windows"
    process = subprocess.Popen(args, shell=not is_windows)
    code = process.wait()
    os.remove(filepath + ".asm")
    if code != 0:
        log("[-] failed.")
        return False

    log("* IDA batchmode success")
    return True


def get_random_string(size):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(size))


def run_ida(ctx: Ctx, input_file: str, script: str, script_args: [str] = []):
    if not is_idb(input_file):
        log("warning: not an idb. Creating " + input_file + ".i64")
        run_ida_batchmode(ctx, input_file)
        input_file += ".i64"

    if len(script) == 0:
        return True

    if len(script_args) == 0:
        prefix = get_random_string(6)
        script_args = ["--quit", "--prefix", prefix]

    # Run `script` with args `script_args` in `ida_database`
    ctx.ida = ctx.ida64 if input_file.endswith(".i64") else ctx.ida32

    args = get_script_exec_args(ctx, input_file, input_file, script, script_args)
    log(f"* running:\t{args}")
    # different quoting behavior between linux & windows...
    is_windows = platform.system() == "Windows"
    process = subprocess.Popen(args, shell=not is_windows)
    code = process.wait()

    output = ""
    with open(ctx.logfile, "r", encoding = "UTF-8") as fh:
        output = fh.read()

    if code == 0:
        log("* IDA script success")
        for line in output.splitlines():
            if not line.startswith(prefix):
                continue

            line.strip()
            line = line[len(prefix) :]
            print(line)
        return True

    errx(ctx, f"Trace:\n{output}")
    log(f"[-] Status code:\t{hex(code)}")
    return False


def get_idb_suffix(filename: str) -> str:
    return ".idb" if filename.endswith(".idb") else ".i64"


def is_idb(filename: str) -> bool:
    return filename.endswith(".i64") or filename.endswith(".idb")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=os.path.abspath, help="input file")
    parser.add_argument("script", type=os.path.abspath, help="IDA script")
    args = parser.parse_args()

    ctx = Ctx()
    ok = run_ida(ctx, args.file, args.script)

    if not ok:
        return 1

    return 0


if __name__ == "__main__":
    main()
