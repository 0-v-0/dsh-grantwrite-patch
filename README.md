# dsh-grantwrite-patch

English | [中文](README.zh.md)

Windows sandbox ACL-repair plugin for DeepSeek Harness (dsh) — fix the grantWrite failure (SetNamedSecurityInfoW Win32 5) and retry the command invisibly.

## What it solves

On Windows, the `workspace-write` sandbox writes a write grant into the workspace root DACL before every command (`AclWriteGrant.add` → `grantWrite`). When any directory on the chain lacks an effective `WRITE_DAC`/`WRITE_OWNER`, `SetNamedSecurityInfoW` fails with Win32 5 (ERROR_ACCESS_DENIED), and **every** confined command on that workspace fails before spawn:

```
Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite
```

This plugin intercepts that error, repairs permissions automatically, and retries the command so you keep working without noticing.

## How it works

The plugin picks a strategy from the workspace size:

- **Normal workspaces**: intercept the error in memory and retry with zero side effects — no file permissions are touched.
- **Large workspaces**: when the object count exceeds the threshold (20,000 by default), proactively apply a full grant to the workspace once, so the write grant is not re-paid on every DSH restart and large trees stop costing you waiting time.
- **Fallback**: when the above cannot apply, run the diagnose script once to repair permissions and retry; when the script is unavailable, fall back to an `icacls` grant.
- **Capability back-fill** (v0.2.0+): on every workspace decision, explicitly back-fill the root's capability SIDs (write SIDs) onto hardened subdirectories that predate the grant (world Deny `FILE_DELETE_CHILD` without a capability Allow) — fixing upstream deepseek-harness [Discussion #423](https://github.com/deepseek-ai/deepseek-harness/discussions/423) / [#9559](https://github.com/deepseek-ai/deepseek-harness/discussions/9559), where pre-existing subdirs can neither be written nor deleted. Independent of the Low label (the deny is a DACL artifact), so it also runs in strict environments; idempotent with its own cooldown, touches only dirs that actually miss the ACE, never touches deny ACEs, and never broadens the grant (only the root's own capability SIDs are reused; Set-Acl constructs the SID directly because icacls cannot resolve S-1-4-*).
- **Background deep back-fill** (v0.2.0+): after the shallow root-level pass, the plugin walks the whole tree (`icacls <root> /T`, async) in the background and back-fills hardened subdirs at *any* depth — node_modules/.git internals included — the equivalent of a manual `fix-delete-acl.ts --all` run, so no manual ACL script is needed. Fire-and-forget, never on the command path; one run per workspace per `probeCooldownMs`; toggle with `deepScan` (default `true`).
- **Low-label cascade repair** (v0.3.0+): fixes the `TS5033 / Access is denied` family. Upstream [Discussion #10379](https://github.com/deepseek-ai/deepseek-harness/discussions/10379) mentions in one sentence that "pnpm hard links may carry the impact into the shared store"; this plugin delivers the complete cascade fix. The sandbox's `grantWrite` stamps an inheritable `Mandatory Label\Low` onto the whole workspace tree; pnpm hard links share the labeled inode between the store and every repo, so any process launched from a labeled exe is forced to Low integrity and cannot write ordinary outputs. Two repair passes: at startup, a background reverse-map (scan known repos' node_modules for labeled natives → `fsutil hardlink list` to find store paths → PE signature check → temp sibling copy + atomic rename to swap the inode); before each confined command, relink still-labeled natives under `<workspace>/node_modules` to the now-clean store inode (when the node_modules directory itself carries the label — a strict workspace — relinking cannot help and is reported as blocked; it needs elevated relabeling or a dsh-side stop of the label stamp). Toggle with `lowLabelRepair` (default `true`); `storeDirs` / `repoScanRoots` / `storeFullScan` are configurable.

The four paths never conflict; they stack on demand.

## Requirements

| Item | Requirement |
|---|---|
| OS | Windows (NTFS). The plugin disables itself on other platforms |
| DSH version | `>= 0.1.7-rc.1`. The full diagnose-script repair needs `>= 0.2.0-rc.2` |
| Sandbox policy | Only `workspace-write` needs this (`read-only` / `danger-full-access` do not) |

## Install

### From npm

```sh
dsh plugin --profile web add dsh-grantwrite-patch
```

### From source (GitHub)

```sh
git clone https://github.com/0-v-0/dsh-grantwrite-patch
cd dsh-grantwrite-patch
pnpm install && pnpm build
dsh plugin --profile web add .
```

Notes:

- `dsh plugin` behaves like adding a dependency to your profile. A bundle plugin is loaded once its full package name appears in the profile's `dsh.profile.bundles` list (added automatically); the bundle patch (`cordis.patch.yml`) applies on the next boot.
- The source install must run `pnpm build` first: `lib/` is not committed, and the FFI preload is resolved from the installed package (`lib/preload.cjs`).
- To update, run the same command again (`add dsh-grantwrite-patch@latest`).
- Alternatively, merge the `- insert:` block of `cordis.patch.yml` into the host's `cordis.yml` by hand.

## Configuration

```yaml
- insert:
    id: grantwrite-patch
    name: dsh-grantwrite-patch
    config:
      enable: true
      mode: auto            # auto | patch | repair
      objectThreshold: 20000    # object count at/above which a workspace counts as large -> persistent repair
      probeTimeoutMs: 10000     # size-probe timeout; a timed-out probe counts as large
      probeCooldownMs: 3600000  # per-workspace probe/decision cache duration
      repairTimeoutMs: 120000
      maxRetries: 1
      cooldownMs: 60000
      appendDiagnostics: true
      grantFallback: true      # fall back to a bare icacls grant when the diagnose script is unavailable (0.1.7) or fails; drive roots refused
      deepScan: true           # background full-tree capability back-fill (fix-delete-acl.ts --all equivalent)
      lowLabelRepair: true     # Low-label cascade repair (background store decontamination + before-command node_modules relink)
      # storeDirs: [<store root>/v11/files]   # pnpm store content dirs; default: env / `pnpm store path` / common paths
      # repoScanRoots: [<repos root>]         # roots reverse-mapped for store pollution
      # storeFullScan: false    # additionally walk every store file (slow); reverse-map only by default
      # scriptPath: <absolute path>   # default: resolved from @deepseek-ai/dsh-sandbox-windows-acl package assets (DSH >= 0.2.x)
      # outDir: <absolute path>       # default: $DSH_HOME/grantwrite-patch (~/.dsh/grantwrite-patch without DSH_HOME)
```

## Security model

- **patch path**: touches no system ACL and leaves no persistent side effect; the `WRITE_RESTRICTED` restricted token, capability-SID Allow ACEs, and the world-SID `FILE_DELETE_CHILD` Deny are preserved. The only thing lost is the Low-integrity label layer of defence in depth (children run at Medium), and only on hosts that could not apply the label in the first place.
- **repair path**: the repair scope is bounded by the script's `-AllowRoot`: only the target directory or objects strictly inside it are modified; reparse points and managed-application trees are refused; deny ACEs are never deleted; every change is backed up first and re-read for verification, and a failed batch is rolled back.
- **grant fallback** (`grantFallback`): when the script is unavailable or fails, run a bare `icacls <root> /grant "<user>:(OI)(CI)F"`. **Drive roots are hard-refused** (`isDriveRoot`: `D:\` and other drive roots are refused; only real workspaces are granted); inheritance policy is untouched and deny ACEs are not removed; roll back with `icacls <root> /remove:g "<user>"`. The script is preferred (safer: `-AllowRoot` bound + backup + verify); the fallback only covers the gap.
- **deep back-fill** (`deepScan`): same capability-SID Allow as the shallow pass, just at any depth; each hit is re-checked before granting (already-fixed dirs are skipped), so it stays idempotent and never broadens the grant. The `/T` walk is background, so it cannot stall the command path; a timed-out scan is reported and retried next window.
- **Low-label repair** (`lowLabelRepair`): only labeled *PE executables* are handled (MZ → e_lfanew → `PE\0\0` + Machine triple check, so mis-detected labels can never rebuild a non-executable); the store swap uses a temp sibling copy + atomic rename (`MoveFileEx` REPLACE semantics) — same content, new inode, the old inode stays alive at the other hard-link points, no delete window, and install concurrency is untouched; the before-command relink verifies the store target is clean first and skips until the next command when the background pass has not converged. When the node_modules directory itself carries the label (a strict workspace), relinking is pointless — a new hard link inherits the directory label — and is honestly reported as blocked, not silently "fixed". The plugin never elevates its token and never touches system policy.
- The plugin process is the host process (a non-restricted token); modifying permissions is exactly what the sandbox's restricted token cannot do. The plugin never elevates its token.
- Only `SetNamedSecurityInfoW` failures in a `grantWrite` context are matched; other Win32 failures, command exit codes, EPERM, and so on all pass through untouched.
- The retry happens once (`maxRetries` is tunable from 0 to 3); a failed repair is not retried, which prevents loops.

## Credits & License

The FFI patch core is adapted from [masknull/dsh-acl-sandbox-patch](https://github.com/masknull/dsh-acl-sandbox-patch).

[MIT](LICENSE)
