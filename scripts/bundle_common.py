"""Build-artifact helpers; output never contains runtime state or credentials."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def host():
    system = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform)
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    if not system or not arch:
        raise RuntimeError("unsupported runner platform")
    return system, arch


def run(command, directory=ROOT, env=None, plan=False):
    print(f"[{directory.relative_to(ROOT)}] {' '.join(map(str, command))}", flush=True)
    if not plan:
        subprocess.run(list(map(str, command)), cwd=directory, env=env, check=True)


def require_file(path):
    if not path.is_file():
        raise RuntimeError(f"build output missing: {path.relative_to(ROOT)}")
    return path


def package(stage, prefix, output, metadata):
    for name in ("LICENSE", "NOTICE.md"):
        shutil.copy2(ROOT / name, stage / name)
    shutil.copytree(ROOT / "third-party", stage / "third-party", dirs_exist_ok=True)
    info = {**metadata, "commit": os.environ.get("GITHUB_SHA", "local-validation"), "compiled_on": platform.system(), "runtimes_bundled": False}
    (stage / "BUILD_INFO.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    files = sorted(path for path in stage.rglob("*") if path.is_file())
    checksums = "".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(stage).as_posix() + "\n" for path in files)
    (stage / "SHA256SUMS").write_text(checksums, encoding="ascii")
    archive = output / (prefix + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                bundle.write(path, prefix + "/" + path.relative_to(stage).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive) + ".sha256").write_text(digest + "  " + archive.name + "\n", encoding="ascii")
    print(f"Artifact: {archive.relative_to(ROOT)}", flush=True)
