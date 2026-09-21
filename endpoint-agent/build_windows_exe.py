#!/usr/bin/env python3
"""
Drishti Endpoint Agent - Windows Distributable Installer (.exe) Builder
Creates an isolated build environment, installs pyinstaller and psutil,
and builds the standalone single-file binary: Drishti-Endpoint-Agent-Windows.exe
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    agent_dir = Path(__file__).resolve().parent
    workspace_root = agent_dir.parent

    venv_dir = agent_dir / ".build-venv"
    dist_dir_local = agent_dir / "dist"
    dist_dir_workspace = workspace_root / "dist"
    build_dir = agent_dir / "build"
    spec_dir = agent_dir

    dist_dir_local.mkdir(parents=True, exist_ok=True)
    dist_dir_workspace.mkdir(parents=True, exist_ok=True)

    print(f"[*] Target agent directory: {agent_dir}")

    # 1. Ensure isolated virtual environment for build
    python_exe = sys.executable
    venv_python = venv_dir / "Scripts" / "python.exe"
    venv_pip = venv_dir / "Scripts" / "pip.exe"
    venv_pyinstaller = venv_dir / "Scripts" / "pyinstaller.exe"

    if not venv_python.exists():
        print(f"[*] Creating build virtual environment at {venv_dir}...")
        subprocess.run([python_exe, "-m", "venv", str(venv_dir)], check=True)

    # 2. Install dependencies into isolated venv
    print("[*] Installing build requirements (psutil, pyinstaller) in build venv...")
    subprocess.run(
        [
            str(venv_pip),
            "install",
            "-r",
            str(agent_dir / "requirements.txt"),
            "pyinstaller>=6.5.0",
            "--quiet",
        ],
        check=True,
    )

    # 3. Assemble PyInstaller command
    exe_name = "Drishti-Endpoint-Agent-Windows"
    cli_entry = agent_dir / "cli.py"

    hidden_imports = [
        "agent",
        "common.config",
        "common.identity",
        "common.lifecycle",
        "common.platform",
        "windows.platform",
        "windows.collectors",
        "collectors.base",
        "collectors.contracts",
        "collectors.manager",
        "transport.client",
        "storage.state",
        "psutil",
    ]

    cmd = [
        str(venv_pyinstaller),
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        exe_name,
        "--paths",
        str(agent_dir),
        "--distpath",
        str(dist_dir_local),
        "--workpath",
        str(build_dir),
        "--specpath",
        str(spec_dir),
    ]

    for hi in hidden_imports:
        cmd.extend(["--hidden-import", hi])

    cmd.append(str(cli_entry))

    print(f"[*] Compiling {exe_name}.exe via PyInstaller...")
    subprocess.run(cmd, check=True)

    output_exe = dist_dir_local / f"{exe_name}.exe"
    if not output_exe.exists():
        raise FileNotFoundError(f"Expected output binary not found: {output_exe}")

    print(f"[+] Successfully built: {output_exe} ({output_exe.stat().st_size / (1024 * 1024):.2f} MB)")

    # 4. Mirror to workspace dist/
    workspace_exe = dist_dir_workspace / f"{exe_name}.exe"
    shutil.copy2(output_exe, workspace_exe)
    print(f"[+] Mirrored executable to workspace: {workspace_exe}")


if __name__ == "__main__":
    main()
