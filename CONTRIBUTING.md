# Contributing

Describe the observable problem and the behavior after the change. Keep device/account data, tokens, CA private keys and runtime state out of changes. Use self-owned local fixture servers and temporary files for regression tests.

Run tests and vet in each changed Go module. UI changes should include a manual check or an appropriate existing fixture test. Optional native features should specify target, compiler, build tags and validation. Document unsupported behavior explicitly instead of returning successful placeholder results.

Keep pinned dependencies and license notices current. Changes to the public CDP adapter must use standard CDP and must not import version hooks/offset tables from an unreviewed provider. Release from a clean checkout; do not copy local runtime directories into artifacts.
