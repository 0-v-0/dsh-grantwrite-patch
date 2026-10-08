# dsh-grantwrite-patch

自动修复 DSH Windows 沙箱的 `Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite` 失败并重试原命令，对模型完全无感。**支持 DSH >= 0.1.7-rc.1**。0.1.7 下仅 FFI patch 生效（该版沙箱包不含诊断脚本 assets，ACL 修复路径 fail-closed）；0.2.x 起沙箱包随 npm 发布 assets，ACL 修复兜底可用。

## 问题

Windows 上 `workspace-write` 沙箱在执行命令前要往工作区根目录 DACL 写写入授权（`AclWriteGrant.add` → `grantWrite`）。当链上某个目录缺有效 `WRITE_DAC`/`WRITE_OWNER` 时，`SetNamedSecurityInfoW` 以 Win32 5（ERROR_ACCESS_DENIED）失败，该工作区**所有**受限命令都在 spawn 前报错：

```
Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite
```

根因：写 Low 完整性标签需要调用者对目录持 `WRITE_OWNER`。非系统盘新建目录默认 ACL 只有 `Authenticated Users: Modify`（无本机用户 FullControl）；DSH 跑 UAC 过滤令牌下，`BUILTIN\Administrators` 是 deny-only 吃不到；属主隐式权限仅 `READ_CONTROL + WRITE_DAC`。上游 Discussions #7771 / #7720 / #7804。

## 策略（默认 auto）

| 模式 | 机制 | 适用 |
|---|---|---|
| **patch**（默认内置） | FFI 层拦截（改编自 [dsh-acl-sandbox-patch](https://github.com/masknull/dsh-acl-sandbox-patch)，MIT）：`SetNamedSecurityInfoW` 先完整尝试，仅 Win32 5 时降级 DACL-only 重试；配套跳过子进程降 Low 完整性、合成标签恢复幂等 skip。**不改任何 ACL** | 普通工作区 |
| **大工作区自动回退** | 命令前探测工作区对象数（遍历到阈值即停，缓存 1h）。超过 `objectThreshold` 时主动跑诊断脚本给工作区补用户 FullControl ACE（持久修复，备份+验证+回滚），使工作区转为严格环境——**避免每次 DSH 重启后首条命令付全树 DACL 传播**（44k 对象 ≈ 20s） | 大工作区 |
| **错误后修复兜底** | 错误路径保留：跑诊断脚本 + 重试一次（**需 DSH >= 0.2.x** 沙箱包 assets；0.1.7 下该路径 fail-closed，仅 FFI patch） | patch 失效/未覆盖通道时 |

三层互不冲突：小工作区靠 patch 零副作用；大工作区修一次后 skip 命中；未来 DSH 沙箱包变化导致 patch 失效时，错误路径兜底照旧工作。

## 插件行为

包装 `ctx.shell` 服务（bash 与 pwsh 工具共用同一实例）：

1. **安装 FFI patch**（`lib/preload.cjs`，零依赖 CJS；源为 src/preload.cts，由 tsc 编译）：koffi 钩子（覆盖所有 node 子进程）+ 沙箱包共享 api 表直改（覆盖服务端 standing grant）。经 `NODE_OPTIONS=--require` 预加载，早于主模块图；插件路径含空格时复制到临时目录。
2. **诊断脚本解析**：运行时从 `@deepseek-ai/dsh-sandbox-windows-acl` 包 assets 解析 `diagnose-windows-sandbox-acl.ps1`（该包自 0.2.x 起随 npm 发布 assets；解析基准 = DSH 服务端入口 + cwd）。包/资产缺失时 repair 路径 fail-closed（FFI patch 继续兜底）。
3. **大工作区判定**（仅 auto 模式）：`resolveRoot(spec)` 后按工作区探测对象数；`objectThreshold`（默认 20000）以上 → 主动 repair。
4. **错误后兜底**：`shell.execute`（或 `shell.run`）抛出的错误匹配 `/SetNamedSecurityInfoW failed \(Win32 \d+\): grantWrite/`（裸错、`AggregateError` 包装、`cause` 链都识别）时，取 `spec.sandboxPolicy.workspaceRoot`（回退 `spec.workdir`），跑诊断脚本（`-Path <root> -AllowRoot <root> -Out $DSH_HOME/grantwrite-patch`），修复验证通过（退出 0 且 RECAP `nextAction=verify_original_confined_operation`）→ **重试原命令一次**；
5. 修复被拒/失败、或重试仍抛同一错误 → 抛回原错误（可附一行 RECAP 摘要），绝不掩盖持续性问题，也绝不无限重试。

并发安全：同一工作区的并发修复请求合并为一次；修复后 60s 冷却窗口内不再重复修；探测判定 1h 缓存。

## 运行要求

| 项 | 要求 |
|---|---|
| 操作系统 | **Windows**（NTFS；其他平台插件自动 no-op） |
| **DSH 最低版本** | **`>= 0.1.7-rc.1`**（`engines.dsh` 已声明）。0.1.7 仅 FFI patch；ACL 修复兜底另需 **`>= 0.2.0-rc.2`**（该版本起沙箱包随 npm 发布 `assets/diagnose-windows-sandbox-acl`） |
| 策略 | 仅 `workspace-write` 需要（`read-only` / `danger-full-access` 不需要） |

## 安装

```sh
pnpm install
pnpm build
```

```sh
dsh plugin --profile web add <本仓库路径>
```

重启宿主后生效。或手动把 `cordis.patch.yml` 的 `- insert:` 段并入宿主 `cordis.yml`。

非 Windows 或没有 `ctx.shell` 的组合下插件 inert（`inject: { shell: null }`）；`mode: "repair"` 时不安装 FFI patch（纯旧行为）。

## 配置

```yaml
- insert:
    id: grantwrite-patch
    name: dsh-grantwrite-patch
    config:
      enable: true
      mode: auto            # auto | patch | repair
      objectThreshold: 20000    # 对象数达到此值视为大工作区，触发持久修复
      probeTimeoutMs: 10000     # 大小探测超时；超时按大工作区处理
      probeCooldownMs: 3600000  # 每工作区探测判定缓存时长
      repairTimeoutMs: 120000
      maxRetries: 1
      cooldownMs: 60000
      appendDiagnostics: true
      # scriptPath: <绝对路径>   # 默认: 从 @deepseek-ai/dsh-sandbox-windows-acl 包 assets 解析 (DSH >= 0.2.x)
      # outDir: <绝对路径>       # 默认: $DSH_HOME/grantwrite-patch（无 DSH_HOME 时 ~/.dsh/grantwrite-patch）
```

## 安全模型

- **patch 路径**：不改任何系统 ACL、无持久副作用；保留 `WRITE_RESTRICTED` 受限令牌、capability SID Allow ACE、world SID `FILE_DELETE_CHILD` Deny。失去的仅是 Low 完整性标签这一层纵深（子进程 Medium），且仅在本来打不上标签的环境发生。
- **repair 路径**：修复范围由脚本的 `-AllowRoot` 硬边界约束：只改目标目录或严格在其内部的对象；reparse 点与托管应用树拒绝；deny ACE 永不删除；每次改动先备份、后重读验证，失败回滚本批改动。
- 插件进程是宿主进程（非受限 token），脚本修改权限正是沙箱受限 token 做不了的事；插件不提升 token。
- 只匹配 `grantWrite` 上下文的 `SetNamedSecurityInfoW` 失败，其他 Win32 失败、命令退出码、EPERM 等一律原样放行。
- 重试只发生一次（`maxRetries` 可调 0–3），修复失败不重试，防止循环。

## 测试

```sh
pnpm test        # 构建 + node:test（34 用例）
pnpm typecheck
pnpm lint
```

## 致谢与许可证

FFI patch 核心改编自 [masknull/dsh-acl-sandbox-patch](https://github.com/masknull/dsh-acl-sandbox-patch)

[MIT](LICENSE)
