[CmdletBinding()]
param([string]$Toolchain = '1.95.0-x86_64-pc-windows-gnu')
$ErrorActionPreference = 'Stop'
$taskRustTarget = 'x86_64-pc-windows-gnu'
$taskClang = Get-Command clang -ErrorAction SilentlyContinue
if (-not $taskClang) { throw 'Install LLVM (clang and LLD) and add its bin directory to PATH.' }
$taskRustRoot = & rustup run $Toolchain rustc --print sysroot
if ($LASTEXITCODE -ne 0) { throw "Install the pinned toolchain: rustup toolchain install $Toolchain --profile minimal" }
$taskLibraries = Join-Path $taskRustRoot "lib\rustlib\$taskRustTarget\lib\self-contained"
if (-not (Test-Path -LiteralPath (Join-Path $taskLibraries 'libgcc_eh.a'))) { throw 'Matching Rust GNU runtime libraries are missing.' }
$taskPreviousFlags = $env:CARGO_ENCODED_RUSTFLAGS
$taskFlags = @('-C', 'link-self-contained=yes', '-C', ('linker=' + $taskClang.Source), '-C', ('link-arg=--target=' + $taskRustTarget), '-C', 'link-arg=-fuse-ld=lld', '-C', ('link-arg=-L' + $taskLibraries))
$env:CARGO_ENCODED_RUSTFLAGS = $taskFlags -join [char]31
Push-Location (Join-Path $PSScriptRoot '..\native\memscan-rs')
try {
  & cargo "+$Toolchain" test --locked --target $taskRustTarget
  if ($LASTEXITCODE -ne 0) { throw 'Native tests failed.' }
} finally {
  Pop-Location
  $env:CARGO_ENCODED_RUSTFLAGS = $taskPreviousFlags
}
