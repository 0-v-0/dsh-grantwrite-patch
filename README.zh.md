# dsh-grantwrite-patch

[English](README.md) | 中文

为 DeepSeek Harness (dsh) 开发的 Windows 沙箱 ACL 修复插件 —— 修复 grantWrite 失败（SetNamedSecurityInfoW Win32 5），并静默重试原命令。

## 它解决什么问题

Windows 上 `workspace-write` 沙箱在执行命令前要往工作区根目录 DACL 写写入授权（`AclWriteGrant.add` → `grantWrite`）。当链上某个目录缺有效 `WRITE_DAC`/`WRITE_OWNER` 时，`SetNamedSecurityInfoW` 以 Win32 5（ERROR_ACCESS_DENIED）失败，该工作区**所有**受限命令都在 spawn 前报错：

```
Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite
```

本插件拦截这个错误，自动修复权限后重试命令，让你无感继续工作。

## 工作方式

插件按工作区大小自动选择策略：

- **普通工作区**：在内存层拦截错误，零副作用地重试，不改任何文件权限。
- **大工作区**：探测到对象过多时（默认超过 2 万），主动给工作区补一次完整权限——这样不用每次都重复授权，省下大目录的等待时间。
- **兜底**：上面的方法失效时，跑诊断脚本修一次权限再重试；脚本不可用时退回 `icacls` 授权。
- **capability 补授**（v0.2.0+）：每次进入工作区时，把根目录的 capability SID（写 SID）显式补授到"授权后出现/已存在"的硬化子目录（有 world Deny `FILE_DELETE_CHILD` 但缺 capability Allow）——修复 dsh 上游 [Discussion #423](https://github.com/deepseek-ai/deepseek-harness/discussions/423)/[#9559](https://github.com/deepseek-ai/deepseek-harness/discussions/9559) 描述的"预存在子目录无法写/删"问题。与 Low label 无关（那是 DACL 产物），严格环境下同样运行；幂等 + 冷却，只在真正缺 ACE 的目录上动手，不碰 deny ACE、不扩大授权（只复用根已有的 capability SID，Set-Acl 直构 SID，icacls 映射不了 S-1-4-*）。
- **后台深层补授**（v0.2.0+）：浅层根一级补授后，插件在后台全树扫描（`icacls <root> /T`，异步）并补授**任意深度**的硬化子目录——含 node_modules/.git 内部——等效于手动跑 `fix-delete-acl.ts --all`，不再需要任何手动 ACL 脚本。fire-and-forget、绝不阻塞命令路径；每个工作区按 `probeCooldownMs` 只跑一次；`deepScan` 开关（默认 `true`）。
- **Low label 连锁修复**（v0.3.0+）：根治 `TS5033 / Access is denied` 一族（上游 [Discussion #10379](https://github.com/deepseek-ai/deepseek-harness/discussions/10379) 只一句带过"pnpm 硬链接会把影响带到共享 store"，本插件给出完整连锁修复）——sandbox 的 `grantWrite` 把可继承的 `Mandatory Label\Low` 盖到工作区整树，pnpm 硬链接把被标 inode 共享给 store 和所有仓库，从被标 exe 启动的进程被强制 Low 完整性、写不了普通输出。插件两路修复：**启动时后台**反向映射（扫已知仓库 node_modules 的被标 native → `fsutil hardlink list` 找 store 路径 → PE 签名校验 → 临时兄弟副本 + 原子改名换 inode），**命令前**把 `<workspace>/node_modules` 里仍被标的 native 重新硬链接到已清洁的 store inode（目录自身带标时无法自愈，报告 blocked，需特权清标或官方停发 label）。`lowLabelRepair` 开关（默认 `true`）、`storeDirs`/`repoScanRoots`/`storeFullScan` 可配。

四种方式互不冲突，按需叠加。

## 运行要求

| 项 | 要求 |
|---|---|
| 操作系统 | Windows（NTFS）。其他平台插件自动不启用 |
| DSH 版本 | `>= 0.1.7-rc.1`。完整诊断脚本修复需 `>= 0.2.0-rc.2` |
| 适用沙箱 | 仅 `workspace-write` 需要（`read-only` / `danger-full-access` 不需要） |

## 安装

### 从 npm 安装

```sh
dsh plugin --profile web add dsh-grantwrite-patch
```

### 从源码安装（GitHub）

```sh
git clone https://github.com/0-v-0/dsh-grantwrite-patch
cd dsh-grantwrite-patch
pnpm install && pnpm build
dsh plugin --profile web add .
```

说明：

- `dsh plugin` 等同于向 profile 添加依赖。bundle 插件的完整包名出现在 profile 的 `dsh.profile.bundles` 列表后即被加载（自动添加）；bundle 补丁（`cordis.patch.yml`）在下一次启动时生效。
- 源码安装必须先跑 `pnpm build`：`lib/` 不入库，且 FFI preload 是从已安装包内解析的（`lib/preload.cjs`）。
- 更新时重新执行相同命令即可（`add dsh-grantwrite-patch@latest`）。
- 也可以手动把 `cordis.patch.yml` 的 `- insert:` 段并入宿主 `cordis.yml`。

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
      grantFallback: true      # 诊断脚本不可用(0.1.7)/失败时回退裸 icacls grant；磁盘根拒绝
      deepScan: true           # 后台全树 capability 补授（fix-delete-acl.ts --all 等效）
      lowLabelRepair: true     # Low label 连锁修复（store 后台去污 + 命令前 node_modules 重链接）
      # storeDirs: [<store root>/v11/files]       # pnpm store 内容目录；默认 env/pnpm store path/常见路径
      # repoScanRoots: [<repos root>]             # 反向映射扫描的仓库根
      # storeFullScan: false    # 额外全扫 store 每个文件（慢）；默认只反向映射
      # scriptPath: <绝对路径>   # 默认: 从 @deepseek-ai/dsh-sandbox-windows-acl 包 assets 解析 (DSH >= 0.2.x)
      # outDir: <绝对路径>       # 默认: $DSH_HOME/grantwrite-patch（无 DSH_HOME 时 ~/.dsh/grantwrite-patch）
```

## 安全模型

- **patch 路径**：不改任何系统 ACL、无持久副作用；保留 `WRITE_RESTRICTED` 受限令牌、capability SID Allow ACE、world SID `FILE_DELETE_CHILD` Deny。失去的仅是 Low 完整性标签这一层纵深（子进程 Medium），且仅在本来打不上标签的环境发生。
- **repair 路径**：修复范围由脚本的 `-AllowRoot` 硬边界约束：只改目标目录或严格在其内部的对象；reparse 点与托管应用树拒绝；deny ACE 永不删除；每次改动先备份、后重读验证，失败回滚本批改动。
- **grant 回退**（`grantFallback`）：脚本不可用或失败时跑裸 `icacls <root> /grant "<user>:(OI)(CI)F`。**磁盘根硬拒**（`isDriveRoot`：`D:\` 等盘根拒绝，只授权真实工作区）；不碰继承策略、不删 deny ACE；可 `icacls <root> /remove:g "<user>"` 回滚。脚本优先（更安全：有 `-AllowRoot` 边界+备份+验证），回退仅兜底。
- **深层补授**（`deepScan`）：与浅层同一 capability-SID Allow，只是任意深度；每个命中目录补授前先复查（已修过的跳过），保持幂等、不扩大授权。`/T` 扫描在后台，不会卡住命令路径；超时扫描会报告、下个窗口重试。
- **Low label 修复**（`lowLabelRepair`）：只处理被标为 Low 的**可执行 PE**（MZ → e_lfanew → `PE\0\0` + Machine 三级校验，杜绝误重建）；store 替换用临时兄弟副本 + 原子改名（`MoveFileEx` REPLACE 语义），内容一致、inode 换新，旧 inode 在其他硬链接点继续存在，无删除窗口、不破坏 install 并发；命令前重链接先验证 store 目标已清洁，未收敛则跳过、下个命令续。node_modules 目录自身被标（严格硬化工作区）时重链接无济于事——新硬链接继承目录标——如实报告 blocked，不假装修复。插件进程不提升 token、不改任何系统策略。
- 插件进程是宿主进程（非受限 token），脚本修改权限正是沙箱受限 token 做不了的事；插件不提升 token。
- 只匹配 `grantWrite` 上下文的 `SetNamedSecurityInfoW` 失败，其他 Win32 失败、命令退出码、EPERM 等一律原样放行。
- 重试只发生一次（`maxRetries` 可调 0–3），修复失败不重试，防止循环。

## 致谢与许可证

FFI patch 核心改编自 [masknull/dsh-acl-sandbox-patch](https://github.com/masknull/dsh-acl-sandbox-patch)

[MIT](LICENSE)
