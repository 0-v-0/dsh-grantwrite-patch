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

The three paths never conflict; they stack on demand.

## Requirements

| Item | Requirement |
|---|---|
| OS | Windows (NTFS). The plugin disables itself on other platforms |
| DSH version | `>= 0.1.7-rc.1`. The full diagnose-script repair needs `>= 0.2.0-rc.2` |
| Sandbox policy | Only `workspace-write` needs this (`read-only` / `danger-full-access` do not) |

## Install

```sh
pnpm install
pnpm build
```

```sh
dsh plugin --profile web add <path-to-this-repo>
```

Restart the host to take effect. Alternatively, merge the `- insert:` block of `cordis.patch.yml` into the host's `cordis.yml` by hand.

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
      # scriptPath: <absolute path>   # default: resolved from @deepseek-ai/dsh-sandbox-windows-acl package assets (DSH >= 0.2.x)
      # outDir: <absolute path>       # default: $DSH_HOME/grantwrite-patch (~/.dsh/grantwrite-patch without DSH_HOME)
```

## Security model

- **patch path**: touches no system ACL and leaves no persistent side effect; the `WRITE_RESTRICTED` restricted token, capability-SID Allow ACEs, and the world-SID `FILE_DELETE_CHILD` Deny are preserved. The only thing lost is the Low-integrity label layer of defence in depth (children run at Medium), and only on hosts that could not apply the label in the first place.
- **repair path**: the repair scope is bounded by the script's `-AllowRoot`: only the target directory or objects strictly inside it are modified; reparse points and managed-application trees are refused; deny ACEs are never deleted; every change is backed up first and re-read for verification, and a failed batch is rolled back.
- **grant fallback** (`grantFallback`): when the script is unavailable or fails, run a bare `icacls <root> /grant "<user>:(OI)(CI)F"`. **Drive roots are hard-refused** (`isDriveRoot`: `D:\` and other drive roots are refused; only real workspaces are granted); inheritance policy is untouched and deny ACEs are not removed; roll back with `icacls <root> /remove:g "<user>"`. The script is preferred (safer: `-AllowRoot` bound + backup + verify); the fallback only covers the gap.
- The plugin process is the host process (a non-restricted token); modifying permissions is exactly what the sandbox's restricted token cannot do. The plugin never elevates its token.
- Only `SetNamedSecurityInfoW` failures in a `grantWrite` context are matched; other Win32 failures, command exit codes, EPERM, and so on all pass through untouched.
- The retry happens once (`maxRetries` is tunable from 0 to 3); a failed repair is not retried, which prevents loops.

## Credits & License

The FFI patch core is adapted from [masknull/dsh-acl-sandbox-patch](https://github.com/masknull/dsh-acl-sandbox-patch).

[MIT](LICENSE)
