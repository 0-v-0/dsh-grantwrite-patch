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

三种方式互不冲突，按需叠加。

## 运行要求

| 项 | 要求 |
|---|---|
| 操作系统 | Windows（NTFS）。其他平台插件自动不启用 |
| DSH 版本 | `>= 0.1.7-rc.1`。完整诊断脚本修复需 `>= 0.2.0-rc.2` |
| 适用沙箱 | 仅 `workspace-write` 需要（`read-only` / `danger-full-access` 不需要） |

## 安装

```sh
pnpm install
pnpm build
```

```sh
dsh plugin --profile web add <本仓库路径>
```

重启宿主后生效。或手动把 `cordis.patch.yml` 的 `- insert:` 段并入宿主 `cordis.yml`。

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
      # scriptPath: <绝对路径>   # 默认: 从 @deepseek-ai/dsh-sandbox-windows-acl 包 assets 解析 (DSH >= 0.2.x)
      # outDir: <绝对路径>       # 默认: $DSH_HOME/grantwrite-patch（无 DSH_HOME 时 ~/.dsh/grantwrite-patch）
```

## 安全模型

- **patch 路径**：不改任何系统 ACL、无持久副作用；保留 `WRITE_RESTRICTED` 受限令牌、capability SID Allow ACE、world SID `FILE_DELETE_CHILD` Deny。失去的仅是 Low 完整性标签这一层纵深（子进程 Medium），且仅在本来打不上标签的环境发生。
- **repair 路径**：修复范围由脚本的 `-AllowRoot` 硬边界约束：只改目标目录或严格在其内部的对象；reparse 点与托管应用树拒绝；deny ACE 永不删除；每次改动先备份、后重读验证，失败回滚本批改动。
- **grant 回退**（`grantFallback`）：脚本不可用或失败时跑裸 `icacls <root> /grant "<user>:(OI)(CI)F`。**磁盘根硬拒**（`isDriveRoot`：`D:\` 等盘根拒绝，只授权真实工作区）；不碰继承策略、不删 deny ACE；可 `icacls <root> /remove:g "<user>"` 回滚。脚本优先（更安全：有 `-AllowRoot` 边界+备份+验证），回退仅兜底。
- 插件进程是宿主进程（非受限 token），脚本修改权限正是沙箱受限 token 做不了的事；插件不提升 token。
- 只匹配 `grantWrite` 上下文的 `SetNamedSecurityInfoW` 失败，其他 Win32 失败、命令退出码、EPERM 等一律原样放行。
- 重试只发生一次（`maxRetries` 可调 0–3），修复失败不重试，防止循环。

## 致谢与许可证

FFI patch 核心改编自 [masknull/dsh-acl-sandbox-patch](https://github.com/masknull/dsh-acl-sandbox-patch)

[MIT](LICENSE)
