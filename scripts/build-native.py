"""Compile native source on runners; keep native injection opt-in."""
import argparse
import os
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
from bundle_common import ROOT, host, package, require_file, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    system, arch = host()
    label = ("macos" if system == "darwin" else system) + "-" + arch
    crate = ROOT / "capx" / "native" / "memscan-rs"
    output = ROOT / "dist" / "native"
    stage = output / ("capx-native-" + label)
    env = os.environ.copy()
    if system == "windows":
        toolchain = "1.95.0-x86_64-pc-windows-gnu"
        target = ["--target", "x86_64-pc-windows-gnu"]
        if not args.plan:
            clang = shutil.which("clang")
            if not clang:
                raise RuntimeError("LLVM clang/LLD is required")
            sysroot = subprocess.check_output(["rustup", "run", toolchain, "rustc", "--print", "sysroot"], text=True).strip()
            libraries = os.path.join(sysroot, "lib", "rustlib", "x86_64-pc-windows-gnu", "lib", "self-contained")
            flags = ["-C", "link-self-contained=yes", "-C", "linker=" + clang, "-C", "link-arg=--target=x86_64-w64-windows-gnu", "-C", "link-arg=-fuse-ld=lld", "-C", "link-arg=-L" + libraries]
            env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
        release = crate / "target" / "x86_64-pc-windows-gnu" / "release"
        names = ["libmemscan.a", "memscan.dll"]
    else:
        toolchain, target = "1.95.0", []
        release = crate / "target" / "release"
        names = ["libmemscan.a", "libmemscan.dylib" if system == "darwin" else "libmemscan.so"]
    if not args.plan:
        stage.mkdir(parents=True, exist_ok=False)
    run(["cargo", "+" + toolchain, "test", "--locked", *target], crate, env, args.plan)
    run(["cargo", "+" + toolchain, "build", "--locked", "--release", *target], crate, env, args.plan)
    if system == "windows":
        sources = ROOT / "capx" / "internal" / "hook" / "native"
        minhook = sources / "minhook" / "src"
        units = [sources / "capx_hook.c", minhook / "buffer.c", minhook / "hook.c", minhook / "trampoline.c", minhook / "hde" / "hde64.c"]
        # cl is activated by msvc-dev-cmd in the workflow, only for this C DLL.
        run(["cl", "/nologo", "/LD", "/O2", *units, "/link", "/OUT:" + str(stage / "capx_hook.dll"), "ws2_32.lib", "psapi.lib"], ROOT, env, args.plan)
    if args.plan:
        return
    for name in names:
        shutil.copy2(require_file(release / name), stage / name)
    shutil.copy2(crate / "include" / "memscan.h", stage / "memscan.h")
    (stage / "RUN.md").write_text("# Native components\n\nThese are opt-in libraries, not the default application bundle. DLL hook injection still requires a Windows native_hook build and separate security/lifecycle review. Static scanner integration uses memscan_ffi and a matching C toolchain. No signing certificate, proprietary installer or capture driver is included.\n", encoding="utf-8")
    package(stage, "capx-native-" + label, output, {"components": ["rust-memscan", "c-hook" if system == "windows" else "rust-ffi"], "profile": "native-libraries", "rust": "1.95.0"})


if __name__ == "__main__":
    main()
