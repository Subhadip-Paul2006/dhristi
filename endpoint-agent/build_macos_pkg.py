#!/usr/bin/env python3
"""
Drishti Endpoint Agent - macOS Distributable Installer (.pkg) Builder
Generates a standard Apple Flat Package (XAR format containing PackageInfo, Payload, Scripts)
compatible with macOS `installer` CLI and macOS Installer.app GUI.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import shutil
import struct
import sys
import zlib
from pathlib import Path


def make_cpio_entry(filename: str, content: bytes, mode: int = 0o100644, ino: int = 1, mtime: int = 1726000000) -> bytes:
    """Creates a single entry in standard SVR4 portable cpio (newc: 070701)."""
    # Normalize paths to use forward slashes and no leading slash
    filename = filename.replace("\\", "/").lstrip("/")
    name_bytes = filename.encode("utf-8") + b"\x00"
    name_len = len(name_bytes)
    filesize = len(content)

    header = (
        f"070701"
        f"{ino:08X}"
        f"{mode:08X}"
        f"{0:08X}"       # uid (root)
        f"{0:08X}"       # gid (wheel)
        f"{1:08X}"       # nlink
        f"{mtime:08X}"   # mtime
        f"{filesize:08X}"
        f"{0:08X}"       # major
        f"{0:08X}"       # minor
        f"{0:08X}"       # rmajor
        f"{0:08X}"       # rminor
        f"{name_len:08X}"
        f"00000000"     # chksum
    ).encode("ascii")

    pad1_len = (4 - ((110 + name_len) % 4)) % 4
    pad2_len = (4 - (filesize % 4)) % 4

    return header + name_bytes + (b"\x00" * pad1_len) + content + (b"\x00" * pad2_len)


def make_cpio_trailer(ino: int = 999999) -> bytes:
    """Creates the standard cpio TRAILER!!! marker."""
    trailer_name = b"TRAILER!!!\x00"
    name_len = len(trailer_name)
    header = (
        f"070701"
        f"{ino:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{1:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{0:08X}"
        f"{name_len:08X}"
        f"00000000"
    ).encode("ascii")
    pad1_len = (4 - ((110 + name_len) % 4)) % 4
    return header + trailer_name + (b"\x00" * pad1_len)


def build_xar_package(files: list[tuple[str, bytes]], output_path: Path) -> None:
    """
    Constructs an Apple Flat Package XAR archive with SHA-1 TOC checksum.
    `files` is a list of (name, bytes) tuples for files in the archive (PackageInfo, Payload, Scripts, etc.).
    """
    heap_data = bytearray()
    # Reserve 20 bytes for SHA1 checksum of TOC at start of heap
    heap_data.extend(b"\x00" * 20)

    file_nodes = []
    for idx, (name, data) in enumerate(files, start=1):
        offset = len(heap_data)
        length = len(data)
        sha1 = hashlib.sha1(data).hexdigest()
        heap_data.extend(data)

        file_nodes.append(f"""  <file id="{idx}">
   <data>
    <length>{length}</length>
    <offset>{offset}</offset>
    <size>{length}</size>
    <extracted-checksum style="sha1">{sha1}</extracted-checksum>
    <archived-checksum style="sha1">{sha1}</archived-checksum>
   </data>
   <type>file</type>
   <name>{name}</name>
  </file>""")

    files_xml = "\n".join(file_nodes)
    toc_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <checksum style="sha1">
   <size>20</size>
   <offset>0</offset>
  </checksum>
{files_xml}
 </toc>
</xar>""".encode("utf-8")

    toc_uncompressed = len(toc_xml)
    toc_comp = zlib.compress(toc_xml)
    toc_compressed = len(toc_comp)

    # Compute TOC SHA1 checksum and place at heap offset 0
    toc_sha1 = hashlib.sha1(toc_comp).digest()
    heap_data[0:20] = toc_sha1

    magic = b"xar!"
    header_size = 28
    version = 1
    cksum_alg = 1  # SHA-1
    header = struct.pack(">4sHHQQI", magic, header_size, version, toc_compressed, toc_uncompressed, cksum_alg)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(header + toc_comp + bytes(heap_data))


def generate_macos_pkg(agent_root: Path, output_file: Path) -> None:
    """Builds the complete macOS .pkg installer."""
    print(f"[*] Packaging Drishti Endpoint Agent for macOS from {agent_root}...")

    # Launcher wrapper script for macOS
    launcher_sh = b"""#!/usr/bin/env bash
# Drishti Endpoint Agent - macOS Launcher
set -e

AGENT_HOME="/Library/Application Support/Drishti/endpoint-agent"
cd "$AGENT_HOME"

# Load global configuration if present
if [ -f "/etc/drishti/agent.conf" ]; then
    set -a
    . "/etc/drishti/agent.conf"
    set +a
fi

# Detect Python 3
PYTHON_BIN=""
for candidate in "$AGENT_HOME/.venv/bin/python" /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[Drishti] ERROR: Python 3 not found on this macOS system." >&2
    echo "[Drishti] Please install Python 3 via Homebrew or Xcode Command Line Tools." >&2
    exit 1
fi

# Auto-setup venv if psutil is not yet installed in host environment
if ! "$PYTHON_BIN" -c "import psutil" >/dev/null 2>&1; then
    if [ ! -d "$AGENT_HOME/.venv" ]; then
        echo "[Drishti] Setting up endpoint agent isolated environment..."
        "$PYTHON_BIN" -m venv "$AGENT_HOME/.venv" >/dev/null 2>&1 || true
        if [ -f "$AGENT_HOME/.venv/bin/pip" ]; then
            "$AGENT_HOME/.venv/bin/pip" install -r "$AGENT_HOME/requirements.txt" -q >/dev/null 2>&1 || true
        fi
    fi
    if [ -f "$AGENT_HOME/.venv/bin/python" ]; then
        PYTHON_BIN="$AGENT_HOME/.venv/bin/python"
    fi
fi

exec "$PYTHON_BIN" "$AGENT_HOME/cli.py" "$@"
"""

    # LaunchDaemon plist template
    launchd_plist = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.drishti.endpointagent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/Drishti/endpoint-agent/drishti-agent-launcher.sh</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/drishti-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/drishti-agent.err</string>
    <key>WorkingDirectory</key>
    <string>/Library/Application Support/Drishti/endpoint-agent</string>
</dict>
</plist>
"""

    # Default configuration file template
    default_conf = b"""# Drishti Endpoint Agent Configuration
# Set the backend URL for your Drishti server instance:
DRISHTI_SERVER_URL=http://localhost:8000
"""

    # postinstall script
    postinstall_sh = b"""#!/bin/bash
set -e

AGENT_DIR="/Library/Application Support/Drishti/endpoint-agent"
chmod -R 755 "$AGENT_DIR"
chmod +x "$AGENT_DIR/drishti-agent-launcher.sh"

mkdir -p "/usr/local/bin"
ln -sf "$AGENT_DIR/drishti-agent-launcher.sh" "/usr/local/bin/drishti-endpoint-agent"
chmod 755 "/usr/local/bin/drishti-endpoint-agent"

mkdir -p "/etc/drishti"
if [ ! -f "/etc/drishti/agent.conf" ]; then
    cat << 'EOF' > /etc/drishti/agent.conf
# Drishti Endpoint Agent Configuration
DRISHTI_SERVER_URL=http://localhost:8000
EOF
    chmod 644 "/etc/drishti/agent.conf"
fi

if [ -d "/Library/LaunchDaemons" ]; then
    cp "$AGENT_DIR/com.drishti.endpointagent.plist" "/Library/LaunchDaemons/com.drishti.endpointagent.plist"
    chmod 644 "/Library/LaunchDaemons/com.drishti.endpointagent.plist"
    chown root:wheel "/Library/LaunchDaemons/com.drishti.endpointagent.plist" 2>/dev/null || true
fi

echo "================================================================="
echo "  Drishti Endpoint Agent installed successfully!"
echo "  Target: $AGENT_DIR"
echo "  Command: drishti-endpoint-agent"
echo "  Configuration: /etc/drishti/agent.conf or --server <URL>"
echo "================================================================="
exit 0
"""

    # Build Payload CPIO entries
    # Target directory on macOS: Library/Application Support/Drishti/endpoint-agent/
    target_prefix = "Library/Application Support/Drishti/endpoint-agent"
    cpio_parts = []
    ino = 100

    # Add directories
    for d in [
        target_prefix,
        f"{target_prefix}/common",
        f"{target_prefix}/macos",
        f"{target_prefix}/collectors",
        f"{target_prefix}/transport",
        f"{target_prefix}/storage",
        "usr/local/bin",
        "etc/drishti",
    ]:
        ino += 1
        cpio_parts.append(make_cpio_entry(d, b"", mode=0o040755, ino=ino))

    # Add wrapper scripts and configs to payload
    ino += 1
    cpio_parts.append(make_cpio_entry(f"{target_prefix}/drishti-agent-launcher.sh", launcher_sh, mode=0o100755, ino=ino))
    ino += 1
    cpio_parts.append(make_cpio_entry(f"{target_prefix}/com.drishti.endpointagent.plist", launchd_plist, mode=0o100644, ino=ino))
    ino += 1
    cpio_parts.append(make_cpio_entry("etc/drishti/agent.conf.default", default_conf, mode=0o100644, ino=ino))

    # Walk endpoint-agent source files (excluding caches, tests, venvs, dist)
    exclude_dirs = {".pytest_cache", "__pycache__", "tests", ".venv", ".build-venv", "dist", "build"}
    for root, dirs, files in os.walk(agent_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".pyc") or f.endswith(".pyo") or f.startswith(".") or f.startswith("build_"):
                continue
            src_file = Path(root) / f
            rel_path = src_file.relative_to(agent_root).as_posix()
            dest_path = f"{target_prefix}/{rel_path}"
            
            with open(src_file, "rb") as sf:
                content = sf.read()
            
            ino += 1
            mode = 0o100755 if f in ("cli.py", "agent.py") else 0o100644
            cpio_parts.append(make_cpio_entry(dest_path, content, mode=mode, ino=ino))

    # Add trailer to payload
    ino += 1
    cpio_parts.append(make_cpio_trailer(ino=ino))
    payload_raw = b"".join(cpio_parts)
    payload_gz = gzip.compress(payload_raw, mtime=0)
    print(f"[*] Payload archive size: {len(payload_gz)} bytes ({len(payload_raw)} uncompressed, {ino - 100} entries)")

    # Build Scripts CPIO
    scripts_parts = [
        make_cpio_entry("postinstall", postinstall_sh, mode=0o100755, ino=1),
        make_cpio_trailer(ino=2),
    ]
    scripts_raw = b"".join(scripts_parts)
    scripts_gz = gzip.compress(scripts_raw, mtime=0)

    # Build PackageInfo XML
    install_kbytes = max(1, (len(payload_raw) + 1023) // 1024)
    package_info = f"""<pkg-info format-version="2" identifier="com.drishti.endpointagent" version="0.1.0" install-location="/" auth="root">
    <payload installKBytes="{install_kbytes}" numberOfFiles="{ino - 100}"/>
    <scripts>
        <postinstall file="./postinstall"/>
    </scripts>
</pkg-info>""".encode("utf-8")

    # Assemble XAR Package
    xar_entries = [
        ("PackageInfo", package_info),
        ("Payload", payload_gz),
        ("Scripts", scripts_gz),
    ]

    build_xar_package(xar_entries, output_file)
    print(f"[+] Successfully generated macOS package: {output_file} ({output_file.stat().st_size} bytes)")


def main():
    agent_dir = Path(__file__).resolve().parent
    workspace_root = agent_dir.parent

    # Output to endpoint-agent/dist/ and workspace dist/
    dist_dir_local = agent_dir / "dist"
    dist_dir_workspace = workspace_root / "dist"
    dist_dir_local.mkdir(parents=True, exist_ok=True)
    dist_dir_workspace.mkdir(parents=True, exist_ok=True)

    pkg_name = "Drishti-Endpoint-Agent-macOS.pkg"
    target_local = dist_dir_local / pkg_name
    target_workspace = dist_dir_workspace / pkg_name

    generate_macos_pkg(agent_dir, target_local)
    shutil.copy2(target_local, target_workspace)
    print(f"[+] Mirrored package to workspace: {target_workspace}")


if __name__ == "__main__":
    main()
