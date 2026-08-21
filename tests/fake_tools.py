"""
Stand-in build tools for the resolver tests.

A resolver's job is to run somebody else's program and make sense of what
comes back, so the tests run a real child process rather than patching
``subprocess``: detection, argument building, working directory, exit codes,
timeouts, temporary files and output parsing are all exercised for real.  Only
the program itself is ours.
"""

import json
import os
import stat
import sys
from pathlib import Path

FAKE_TOOL = '''\
import json
import sys
import time
from pathlib import Path

me = Path(__file__)
config = json.loads(me.with_suffix(".config.json").read_text(encoding="utf-8"))

record = me.with_suffix(".invocations.json")
calls = json.loads(record.read_text(encoding="utf-8")) if record.exists() else []
calls.append({"argv": sys.argv[1:], "cwd": str(Path.cwd())})
record.write_text(json.dumps(calls), encoding="utf-8")

if config.get("version") and any(
        arg in ("--version", "-v", "-version", "version") for arg in sys.argv[1:]):
    sys.stdout.write(config["version"])
    sys.exit(0)

if config.get("delay"):
    time.sleep(config["delay"])

payload = config.get("payload")
flag = config.get("output_file_flag")
if payload is not None and flag:
    target = None
    for arg in sys.argv[1:]:
        if arg.startswith(flag):
            target = arg[len(flag):]
    if target is not None:
        mode = "a" if config.get("append_flag") in sys.argv[1:] else "w"
        with open(target, mode, encoding="utf-8") as handle:
            handle.write(payload)
elif payload is not None:
    sys.stdout.write(payload)

sys.stdout.write(config.get("stdout", ""))
sys.stderr.write(config.get("stderr", ""))
sys.exit(config.get("exit_code", 0))
'''


def _implementation_path(directory: Path, name: str) -> Path:
    return directory / "_{}_tool.py".format(name.split(".")[0])


def install_fake_tool(directory: Path, name: str, *, payload=None, stdout="",
                      stderr="", exit_code=0, delay=0, version=None,
                      output_file_flag=None, append_flag=None,
                      runnable: bool = True) -> Path:
    """
    Write an executable stand-in called ``name`` into ``directory``.

    ``payload`` is what the tool "produces": written to the path named by
    ``output_file_flag`` when there is one, printed to stdout otherwise.
    """
    directory.mkdir(parents=True, exist_ok=True)
    script = _implementation_path(directory, name)
    script.write_text(FAKE_TOOL, encoding="utf-8")

    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload)
    script.with_suffix(".config.json").write_text(json.dumps({
        "payload": payload,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "delay": delay,
        "version": version,
        "output_file_flag": output_file_flag,
        "append_flag": append_flag,
    }), encoding="utf-8")

    launcher = directory / name
    if not runnable:
        launcher.write_text("")        # present, but nothing the OS can run
        return launcher

    if name.endswith((".cmd", ".bat")):
        launcher.write_text(
            "@echo off\r\n"
            f'"{sys.executable}" "{script}" %*\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
    else:
        launcher.write_text(
            "#!/bin/sh\n" f'exec "{sys.executable}" "{script}" "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return launcher


def executable_name(base: str) -> str:
    """The filename a fake tool needs on this platform to be runnable."""
    return f"{base}.cmd" if os.name == "nt" else base


def invocations(directory: Path, name: str) -> list:
    """Every call the fake tool recorded: argv and working directory."""
    record = _implementation_path(directory, name).with_suffix(".invocations.json")
    if not record.exists():
        return []
    return json.loads(record.read_text(encoding="utf-8"))


def install_on_path(monkeypatch, checkdeps_module, **tools) -> None:
    """Make ``shutil.which`` answer with the given {command: path} mapping."""
    resolved = {name: str(path) for name, path in tools.items()}
    monkeypatch.setattr(checkdeps_module.shutil, "which",
                        lambda command: resolved.get(command))
