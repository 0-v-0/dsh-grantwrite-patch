// 钩子共享常量与判定逻辑的单一来源:install-hooks.ts 按标记切片嵌入 .githooks/*(钩子仅能用 node: 内置模块,片段内不得用 ESM 语法);
// verify-*.ts import 本模块并与钩子正文比对,避免多份逻辑手工同步
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SHARED_END = '// ---- 共享片段结束 ----'
const SHARED_REGIONS = {
	commitMsg: '// ---- 共享片段开始:commit-msg 判定 ----',
	constants: '// ---- 共享片段开始:常量 ----',
	preCommit: '// ---- 共享片段开始:pre-commit 判定 ----',
}

// 取标记间源码(不含标记行);标记须在行首匹配避免误命中
// 按 region 记忆化;失败不写缓存,便于修复后重试
const snippetCache = new Map()
export function readSharedSnippet(region: string): string {
	const beginMark = SHARED_REGIONS[region]
	if (!beginMark) {
		throw new Error(`[hook-logic] unknown shared snippet region: ${region}`)
	}
	if (snippetCache.has(region)) {
		return snippetCache.get(region)
	}
	const src = readFileSync(fileURLToPath(import.meta.url), 'utf8')
	const begin = src.indexOf(`\n${beginMark}\n`)
	if (begin === -1) {
		throw new Error(`[hook-logic] marker not found at line start: ${beginMark}`)
	}
	const end = src.indexOf(`\n${SHARED_END}\n`, begin)
	if (end === -1) {
		throw new Error(`[hook-logic] end marker not found after: ${beginMark}`)
	}
	const start = begin + 1 + beginMark.length + 1
	const snippet = src.slice(start, end).replace(/[\r\n]+$/, '')
	snippetCache.set(region, snippet)
	return snippet
}

// ---- 共享片段开始:常量 ----
// 拦截绝对路径:
//   - Windows 盘符:字母+冒号+单 \ 或 /,排除 X:\\ 转义、URL scheme、相对引用
//   - POSIX 系统目录:/ + 白名单目录 + 可选一级名(≥1 字符,允许非 ASCII);单段(如 etc)也命中;
//     前字符非路径成分字符,排除相对引用、URL 与正则字面量相邻段;i 覆盖大小写
const ABS_PATH =
	/(?:^|[^A-Za-z])([A-Za-z]:[\u005c/](?![\u005c/]))|(?<![A-Za-z0-9_.\u002f-])(\u002f(?:home|Users|root|etc|usr|var|opt|srv|tmp|mnt|media|data|bin|lib|dev|proc|sys|run|boot|sbin)(?:\u002f(?:[^\s\u002f]|$))?)/i
// glob 模式豁免:**/lib/**、/lib/*.ts、src/{a,b} 是通配符而非真实机器路径,不应被拦。
// 实现按空白/引号切 token 逐个判定(而非整行),避免邻近的通配符把真路径放过;
// 仅当通配符与 '/' 或另一通配符相邻才算 glob 形状,正文里的孤立 '?' 仍会被拦。
const GLOB_CHARS = new Set(['*', '?', '[', ']', '{', '}'])
const TOKEN_SPLIT = /[\s'"`]+/
function tokenHasGlobShape(token) {
	for (let i = 0; i < token.length; i++) {
		if (!GLOB_CHARS.has(token[i])) {
			continue
		}
		const prev = i > 0 ? token[i - 1] : ''
		const next = i + 1 < token.length ? token[i + 1] : ''
		if (GLOB_CHARS.has(prev) || prev === '/' || GLOB_CHARS.has(next) || next === '/') {
			return true
		}
	}
	return false
}
// 行内是否含真实绝对路径:逐 token 判定,glob 形状 token 直接跳过
function hasAbsolutePath(line) {
	for (const token of line.split(TOKEN_SPLIT)) {
		if (token === '' || tokenHasGlobShape(token)) {
			continue
		}
		// 纯盘根放行
		if (/^[^A-Za-z]*[A-Za-z]:[\\/]?[^A-Za-z0-9_]*$/.test(token)) {
			continue
		}
		if (ABS_PATH.test(token)) {
			return true
		}
	}
	return false
}
// subject 须 \S 开头;body 不强制
const CONVENTIONAL =
	/^(feat|fix|refactor|docs|chore|perf|test|build|ci|style|revert)(\([^()\r\n]+\))?(!)?: \S.*$/
// fixup!/squash!/amend! 前缀(git 自动生成),目标须匹配 Conventional 或 ≥7 位短哈希
const GIT_PREFIX = /^(fixup|squash|amend)! /
// 与 GIT_PREFIX 同集合,空白贪婪(\s+),用于取出 target
const FIXUP_PREFIX = /^(fixup|squash|amend)!\s+/
const SHORT_HASH = /^\s*[0-9a-f]{7,40}\s*$/
// ---- 共享片段结束 ----

// ---- 共享片段开始:commit-msg 判定 ----
// 去掉 git 追加的 # 注释行与空行
function filterCommitLines(raw) {
	return raw.split(/\r?\n/).filter((line) => line.length > 0 && !line.startsWith('#'))
}
// 判定顺序:绝对路径 → fixup 目标 → Conventional 格式
function checkCommitSubject(lines) {
	const absHit = lines.find((line) => hasAbsolutePath(line))
	if (absHit) {
		return { hit: absHit, kind: 'abs', pass: false }
	}
	const subject = lines[0] ?? ''
	if (GIT_PREFIX.test(subject)) {
		const m = subject.match(FIXUP_PREFIX)
		const target = m ? subject.slice(m[0].length) : subject
		if (CONVENTIONAL.test(target) || SHORT_HASH.test(target)) {
			return { hit: '', kind: null, pass: true }
		}
		return { hit: subject, kind: 'target', pass: false }
	}
	if (CONVENTIONAL.test(subject)) {
		return { hit: '', kind: null, pass: true }
	}
	return { hit: subject, kind: 'format', pass: false }
}
// ---- 共享片段开始:pre-commit 判定 ----
// 跳过 node_modules/.git/.githooks 与钩子脚本自身(verify 含绝对路径测试数据、install-hooks 内嵌 shebang,避免自匹配);
// 目录按首段、文件按完整路径精确匹配,防 ../x 误跳
const SKIP_DIRS = new Set(['node_modules', '.git', '.githooks', 'test'])
const SKIP_FILES = new Set([
	'scripts/install-hooks.ts',
	'scripts/verify-hook-regex.ts',
	'scripts/verify-commit-msg.ts',
])
// 变长参数:任一命中即跳过。
// rename 场景下 diff 头为 `a/<旧路径> b/<新路径>`,两侧必须同时参与判定:
// 迁移期旧名(如 .mjs)不在 SKIP_FILES 而新名在,仅按旧名判断会让本该跳过的文件被扫描,
// 其内嵌的测试数据(UNC/绝对路径字面量)随即触发误报。
function isSkippedPath(...files) {
	for (const file of files) {
		if (!file) {
			continue
		}
		if (SKIP_FILES.has(file)) {
			return true
		}
		const slash = file.indexOf('/')
		const top = slash === -1 ? file : file.slice(0, slash)
		if (SKIP_DIRS.has(top)) {
			return true
		}
	}
	return false
}
function isOffendingAddedLine(line) {
	return (
		line.startsWith('+') &&
		!line.startsWith('+++') &&
		!/^\+\s*#!/.test(line) &&
		hasAbsolutePath(line)
	)
}
// ---- 共享片段结束 ----

// ---- 非共享区:install/verify 共用工具(位于片段之外,不进 .githooks 嵌入正文) ----
// 共享片段区域整体嵌入 .githooks 钩子(纯 JS,不能用 TS 语法),区域内不得出现类型注解;
// 区域外工具函数可补类型注解,由 tsconfig.scripts.json 校验
function readHookTemplate(name: string, label: string): string {
	const p = join(dirname(fileURLToPath(import.meta.url)), '..', '.githooks', name)
	if (!existsSync(p)) {
		throw new Error(`[${label}] .githooks/${name} 不存在,请先运行: node scripts/install-hooks.ts`)
	}
	const raw = readFileSync(p, 'utf8')
	const nl = raw.indexOf('\n')
	return nl === -1 ? raw : raw.slice(nl + 1)
}
// 片段过期即生成物落后于 hook-logic.ts,校验的不是最新逻辑

function assertSnippetsFresh(
	template: string,
	regions: string[],
	label: string,
	hookName: string,
): void {
	for (const region of regions) {
		if (!template.includes(readSharedSnippet(region))) {
			console.error(
				`[${label}] .githooks/${hookName} 的共享片段(${region})已过期或缺失,请先运行: node scripts/install-hooks.ts`,
			)
			process.exit(1)
		}
	}
}

export {
	ABS_PATH,
	CONVENTIONAL,
	GIT_PREFIX,
	FIXUP_PREFIX,
	SHORT_HASH,
	checkCommitSubject,
	filterCommitLines,
	hasAbsolutePath,
	isOffendingAddedLine,
	isSkippedPath,
	tokenHasGlobShape,
	readHookTemplate,
	assertSnippetsFresh,
}
