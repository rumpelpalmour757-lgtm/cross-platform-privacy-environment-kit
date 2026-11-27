"""A rough Windows simulation for the Linux CI job. Not part of the kit; only CI loads it.

What this is: at start-up Python imports a module named ``sitecustomize`` if one is on
sys.path. The "Windows 模拟" step of .github/workflows/tests.yml puts this folder on
PYTHONPATH, so every Python process of that test run, including the child processes the
tests start, picks up a few things Windows does differently. Nothing else puts this folder on
sys.path: the kit's scripts and ``python -m unittest`` run without it, and the folder sits under
tools/, which .gitattributes keeps out of the release ZIP. On Windows itself it does nothing.

Each behaviour has its own switch (set to 1 to turn it on):

WINSIM_STDIN_CRLF  Text-mode input given to a child process (``subprocess.run(input=...,
                   text=True)``, ``Popen.communicate``) goes down the pipe with every "\\n"
                   turned into "\\r\\n", as the pipe's TextIOWrapper does on Windows.
WINSIM_OPEN_CRLF   Files opened for writing in text mode with the default newline=None
                   are written with "\\r\\n" line endings, as on Windows.
WINSIM_EXPANDUSER  "~name" follows ntpath's rule: a folder called "name" next to the home
                   folder, instead of the passwd lookup (or the error for an unknown user)
                   on POSIX. Covers os.path.expanduser and pathlib's Path.expanduser.

The CI step sets three more conditions outside this file: TMPDIR is a symbolic link (the path
tempfile hands out differs from its resolved path, as with the 8.3 short names of the Windows
runner's temp folder), that path has spaces and Chinese characters in it (some of them missing
from cp950), and PYTHONIOENCODING=cp950 (the output encoding of Traditional Chinese Windows when
output goes to a pipe or a file).

This is an approximation. It does not change os.sep, sys.platform, drive letters, file-name
case rules, path length limits, file locking or permissions; tests that only run on Windows
still skip here. The real Windows run is the windows-latest job.

To run it locally from the repository root (Linux or macOS):

    mkdir -p "/tmp/winsim 临时 測試/real" && ln -sfn "/tmp/winsim 临时 測試/real" "/tmp/winsim 临时 測試/link"
    PYTHONPATH=tools/ci WINSIM_STDIN_CRLF=1 WINSIM_OPEN_CRLF=1 WINSIM_EXPANDUSER=1 \\
        PYTHONIOENCODING=cp950 TMPDIR="/tmp/winsim 临时 測試/link" \\
        python -B -c "import sitecustomize; sitecustomize.self_check()"
    (same variables) python -B -m unittest discover -p "test_*.py" -v
"""
import os
import sys

SWITCHES = ("WINSIM_STDIN_CRLF", "WINSIM_OPEN_CRLF", "WINSIM_EXPANDUSER")


def _on(name):
    return os.name != "nt" and os.environ.get(name) == "1"


if _on("WINSIM_STDIN_CRLF"):
    import subprocess

    _communicate = subprocess.Popen.communicate

    def _communicate_crlf(self, input=None, timeout=None):
        if self.text_mode and isinstance(input, str):
            input = input.replace("\n", "\r\n")
        return _communicate(self, input, timeout)

    subprocess.Popen.communicate = _communicate_crlf


if _on("WINSIM_OPEN_CRLF"):
    import builtins
    import io

    _open = io.open

    class _CrlfOpen:
        # A callable object rather than a function: Python 3.10's pathlib keeps io.open as a
        # class attribute, where a plain function would be bound as a method.
        def __call__(self, file, mode="r", buffering=-1, encoding=None, errors=None, newline=None,
                     closefd=True, opener=None):
            if "b" not in mode and any(flag in mode for flag in "wax+") and newline is None:
                newline = "\r\n"
            return _open(file, mode, buffering, encoding, errors, newline, closefd, opener)

    io.open = builtins.open = _CrlfOpen()


if _on("WINSIM_EXPANDUSER"):
    import posixpath

    _expanduser = posixpath.expanduser

    def _expanduser_nt(path):
        text = os.fspath(path)
        if not isinstance(text, str) or not text.startswith("~"):
            return _expanduser(path)
        end = 1
        while end < len(text) and text[end] not in "/\\":
            end += 1
        home = os.environ.get("HOME")  # stands in for USERPROFILE
        if not home:
            return text  # ntpath leaves the path alone when there is no profile folder
        if end > 1:
            import getpass

            # ntpath reads the current user from USERNAME; fall back to the POSIX login name.
            wanted, current = text[1:end], os.environ.get("USERNAME") or getpass.getuser()
            if wanted != current:
                parent, last = posixpath.split(home.rstrip("/") or "/")
                if last != current:
                    return text  # the home folder is not named after the user: ntpath gives up
                home = posixpath.join(parent, wanted)
        return home + text[end:]

    posixpath.expanduser = _expanduser_nt
    # Python 3.10's pathlib copies os.path.expanduser when it is imported; catch that copy
    # too in case pathlib was imported before this module.
    _pathlib = sys.modules.get("pathlib")
    if _pathlib is not None and hasattr(_pathlib, "_NormalAccessor"):
        _pathlib._NormalAccessor.expanduser = staticmethod(_expanduser_nt)


def self_check():
    """Show what the simulation changed and fail if a switch that is on did not take effect."""
    import pathlib
    import subprocess
    import tempfile

    sys.stdout.reconfigure(errors="backslashreplace")
    problems = []
    active = [name for name in SWITCHES if _on(name)]
    print("sitecustomize:", __file__)
    print("switches on:", ", ".join(active) or "none")
    if not active:
        problems.append("no WINSIM_* switch is on")
    if "WINSIM_STDIN_CRLF" in active:
        echoed = subprocess.run(
            [sys.executable, "-c", "import sys; sys.stdout.write(repr(sys.stdin.buffer.read()))"],
            input="a\nb\n", capture_output=True, text=True, check=True).stdout
        print("child stdin bytes:", echoed)
        if echoed != repr(b"a\r\nb\r\n"):
            problems.append("text-mode child input is not CRLF")
    if "WINSIM_OPEN_CRLF" in active:
        with tempfile.TemporaryDirectory() as folder:
            sample = pathlib.Path(folder, "crlf.txt")
            sample.write_text("a\nb\n", encoding="utf-8")
            written = sample.read_bytes()
        print("text file bytes:", written)
        if written != b"a\r\nb\r\n":
            problems.append("text-mode file writes are not CRLF")
    if "WINSIM_EXPANDUSER" in active:
        guessed = os.path.expanduser("~winsim-nobody/x")
        try:
            via_pathlib = str(pathlib.Path("~winsim-nobody/x").expanduser())
        except RuntimeError as error:
            via_pathlib = f"RuntimeError: {error}"
        print("expanduser('~winsim-nobody/x'):", guessed, "| Path:", via_pathlib)
        if guessed.startswith("~") or via_pathlib != guessed:
            problems.append("~name is not expanded the ntpath way (is HOME named after the user?)")
    temp = tempfile.gettempdir()
    print("tempfile.gettempdir():", temp)
    print("resolved:", os.path.realpath(temp))
    print("stdout encoding:", sys.stdout.encoding, "| PYTHONIOENCODING:", os.environ.get("PYTHONIOENCODING"))
    for problem in problems:
        print("WINSIM FAILED:", problem)
    if problems:
        raise SystemExit(1)
