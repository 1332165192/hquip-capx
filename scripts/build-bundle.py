"""Build every application from source on the matching GitHub runner."""
from pathlib import Path
import argparse
import os
import shutil
import sys

sys.dont_write_bytecode = True
from bundle_common import ROOT, host, package, require_file, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--plan", action="store_true", help="print commands without compiling or writing files")
    args = parser.parse_args()
    system, arch = host()
    suffix = ".exe" if system == "windows" else ""
    label = ("macos" if system == "darwin" else system) + "-" + arch
    output = ROOT / "dist" / "ci"
    stage = output / ("capx-" + label)
    if not args.plan:
        stage.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env["GOOS"], env["GOARCH"] = system, arch
    env["GOFLAGS"] = "-mod=readonly"
    desktop_tags = ["-tags", "webkit2_41"] if system == "linux" else []
    if args.test:
        for module in ("capx", "capx-web-manager", "capx-desktop"):
            tags = desktop_tags if module == "capx-desktop" else []
            run(["go", "test", *tags, "./..."], ROOT / module, env, args.plan)
            run(["go", "vet", *tags, "./..."], ROOT / module, env, args.plan)
    commands = [("captured", "capx-captured"), ("capx-mcp", "capx-mcp"), ("capx-desktop", "capx-launcher")]
    for source, filename in commands:
        run(["go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", stage / (filename + suffix), "./cmd/" + source], ROOT / "capx", env, args.plan)
    run(["go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", stage / ("capx-web-manager" + suffix), "."], ROOT / "capx-web-manager", env, args.plan)
    # Frontend files are maintained HTML/CSS/JS, already present in the source.
    # Keep pinned go.mod and checked-in bindings unchanged during packaging.
    wails = ["wails", "build", "-m", "-nosyncgomod", "-skipbindings", "-trimpath", "-s", "-platform", system + "/" + arch, *desktop_tags]
    if system == "windows":
        wails.extend(["-webview2", "browser"])
    run(wails, ROOT / "capx-desktop", env, args.plan)
    if args.plan:
        return
    desktop = ROOT / "capx-desktop" / "build" / "bin"
    if system == "darwin":
        app = desktop / "capx-desktop.app"
        if not app.is_dir():
            raise RuntimeError("Wails macOS application bundle is missing")
        target = stage / app.name
        shutil.copytree(app, target)
        shutil.copy2(stage / "capx-captured", target / "Contents" / "MacOS" / "capx-captured")
    else:
        shutil.copy2(require_file(desktop / ("capx-desktop" + suffix)), stage / ("capx-desktop" + suffix))
    for _, filename in commands:
        require_file(stage / (filename + suffix))
    require_file(stage / ("capx-web-manager" + suffix))
    (stage / "RUN.md").write_text("# Running the compiled bundle\n\nLaunch capx-desktop for the Wails UI, or capx-launcher for the Chromium window. The capx-captured backend is beside the desktop executable; capx-mcp connects to a running backend. Use your own instance token and phone CA trust settings. WeChat, ADB, WDA, WebView2, Frida and capture drivers are installed separately.\n", encoding="utf-8")
    package(stage, "capx-" + label, output, {"components": ["captured", "mcp", "launcher", "web-manager", "wails-desktop"], "profile": "default", "go": "1.26.9", "wails": "2.12.0"})


if __name__ == "__main__":
    main()
