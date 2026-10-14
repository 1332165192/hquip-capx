"""Fail on private runtime files or credential formats in the public tree."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
blocked_dirs = {"work-space", "state", "runtime", "devimages", ".npcap-sdk", ".frida-runtime", ".cargo-home", ".rustsetup", "target", "node_modules", ".capx", "__pycache__"}
blocked_suffixes = {".exe", ".dll", ".sys", ".ipa", ".plist", ".p12", ".pfx", ".pem", ".key", ".mobileprovision", ".sqlite", ".db", ".log", ".pcap", ".pcapng", ".a", ".o", ".obj", ".lib", ".so", ".dylib", ".pyc", ".pyo", ".png", ".jpg"}
# Avoid echoing matched credentials. Locations alone are enough to fix a finding.
formats = [re.compile(rb"db-vip-[A-Za-z0-9_-]{20,}"), re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]{64,}"), re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"), re.compile(rb"AKIA[A-Z0-9]{16}")]
# Reviewed public-UI illustrations use synthetic fixtures and carry a visible
# mock-data label. Other images, including real phone screenshots, stay blocked.
documentation_images = {
    "docs/images/01-dashboard.png",
    "docs/images/02-http-analysis.png",
    "docs/images/03-mobile-capture.png",
}
findings = []
for path in root.rglob("*"):
    relative = path.relative_to(root)
    if ".git" in relative.parts:
        continue
    if path.is_symlink():
        findings.append((str(relative), "symlink"))
        continue
    if not path.is_file():
        continue
    is_wails_runtime = relative.parts[:4] == ("capx-desktop", "frontend", "wailsjs", "runtime")
    is_documentation_image = relative.as_posix() in documentation_images
    if (blocked_dirs.intersection(relative.parts) and not is_wails_runtime) or (path.suffix.lower() in blocked_suffixes and not is_documentation_image) or path.name.startswith(".env"):
        findings.append((str(relative), "private or generated file"))
    if is_documentation_image and not path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        findings.append((str(relative), "documentation image is not PNG"))
    # Test fixtures may intentionally include sample PEM keys; review those
    # separately. Never allow an identity or captured credential file itself.
    if path.name != "check-source.py" and not path.name.endswith("_test.go"):
        content = path.read_bytes()
        if any(pattern.search(content) for pattern in formats):
            findings.append((str(relative), "credential format"))
for name, reason in findings:
    print(f"{reason}: {name}")
print(f"Source boundary: {len(findings)} findings")
sys.exit(bool(findings))
