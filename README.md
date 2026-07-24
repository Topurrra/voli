# voli

⚡ A fast, no-admin package manager for Windows. One binary, clean uninstalls, zero scripts.

> **Status: early development — not usable yet.** The scaffold compiles; the
> install engine, index, and registry are still being built.

## Guarantees (never violated)

1. **Never requires admin.** Never touches HKLM or Program Files.
2. **Clean uninstall.** `voli uninstall x` leaves zero trace — directory, shims,
   env vars, and PATH entries are all removed.
3. **No scripts, ever.** Install is download → verify hash → extract → shim →
   (consented) env vars. A package cannot run code on your machine.
4. **Everything is pinned.** Every artifact is sha256-verified; the index is
   Ed25519-signed.

## Planned commands

```
voli install ripgrep fd fzf
voli uninstall ripgrep
voli update
voli upgrade --all
voli list
voli search regex
voli info ripgrep
voli doctor
```

Not implemented yet — every subcommand currently exits with "not implemented".
