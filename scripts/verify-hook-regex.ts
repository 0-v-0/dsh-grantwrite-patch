// 校验 pre-commit 行判定逻辑,并比对钩子内嵌共享片段是否过期
import {
	assertSnippetsFresh,
	isOffendingAddedLine,
	isSkippedPath,
	readHookTemplate,
} from './hook-logic.ts'

console.log(
	'[verify-hook-regex] 用法: node scripts/verify-hook-regex.ts(校验 pre-commit 钩子行判定逻辑,先运行 node scripts/install-hooks.ts 生成钩子)',
)

// 钩子缺失即未安装
let template
try {
	template = readHookTemplate('pre-commit', 'verify-hook-regex')
} catch (err) {
	console.error(err.message)
	process.exit(1)
}
assertSnippetsFresh(template, ['constants', 'preCommit'], 'verify-hook-regex', 'pre-commit')

const skipCases = [
	['node_modules/x', true, 'node_modules 目录跳过'],
	['.git/COMMIT_EDITMSG', true, '.git 目录跳过'],
	['.githooks/pre-commit', true, '.githooks 目录跳过'],
	['scripts/verify-hook-regex.ts', true, 'verify 脚本文件跳过'],
	['scripts/verify-commit-msg.ts', true, 'verify 脚本文件跳过'],
	['scripts/install-hooks.ts', true, 'install 脚本(内嵌 shebang)跳过'],
	['scripts/verify-hook-regex.ts/../x', false, '路径穿越不得前缀误跳'],
	['scripts/verify-commit-msg.ts.bak', false, '同前缀文件不得误跳'],
	['scripts/hook-logic.ts', false, '普通脚本不跳过'],
	['src/node_modules/x', false, '仅根级目录才跳过'],
	// rename:第 4 项为 b/ 侧新名,双侧任一命中即跳过
	[
		'scripts/verify-commit-msg.mjs',
		true,
		'rename 旧名命中(新名在跳过表)',
		'scripts/verify-commit-msg.ts',
	],
	['scripts/verify-commit-msg.mjs', false, 'rename 旧名未配对新名时不得放宽'],
]
let skipFailed = 0
for (const [file, expected, label, alt] of skipCases) {
	const got = alt === undefined ? isSkippedPath(file) : isSkippedPath(file, alt)
	if (got !== expected) skipFailed += 1
	console.log(
		`${got === expected ? 'PASS' : 'FAIL'}  expect=${expected}  got=${got}  :: skip :: ${label} :: ${file}`,
	)
}

const cases = [
	['+D:\\gh\\gh.exe', true, 'drive letter single backslash'],
	["+  cwd: 'D:\\Documents\\repo'", true, 'indented drive path'],
	['+D:/ai/gh.exe', true, 'drive letter forward slash'],
	['+C:\\Users\\me\\file', true, 'Users drive path'],
	["+  path: '<workspace>/code'", false, 'placeholder, not absolute'],
	["+const RULES = 'scripts\\cmem-rules.mjs';", false, 'single backslash, no drive letter'],
	["+const X = 'D:\\\\gh\\\\gh.exe';", false, 'double backslash escape (JS literal)'],
	['+https://example.com/x', false, 'URL scheme'],
	['+doc://some/doc', false, 'doc scheme'],
	['+memory://space/id', false, 'memory scheme'],
	['+  ref: http://localhost:9/x', false, 'URL with port'],
	['+/cmem-rules.*', false, 'gitignore root-anchored pattern'],
	['+#!/usr/bin/env node', false, 'shebang'],
	['+  #!/usr/bin/env node', false, 'indented shebang in docs'],
	['+++ b/D:\\repo\\file.js', false, 'diff file-header (+++) not an added line'],
	['+ls /etc/passwd', true, 'POSIX system dir after space'],
	['+cd /home/user && git status', true, 'POSIX /home/user'],
	['+cd /etc', true, 'bare POSIX system dir (single segment)'],
	['+export PATH=/usr/bin', true, 'POSIX after = (drive branch not involved)'],
	['+/home/张三', true, 'non-ASCII first-level dir name'],
	['+    return /re/g.test(x)', false, 'regex literal - /re/ no whitespace before'],
	['+    const re = /abc/', false, 'regex literal (no dir after slash)'],
	['+a / b', false, 'arithmetic'],
	['+  n = a / b + c', false, 'arithmetic'],
	['+/usr/bin/env', true, 'POSIX /usr/bin at line start'],
	['+/tmp/x', true, 'POSIX /tmp'],
	['+  cd /var/log && tail', true, 'indented /var'],
	["+  dir: '/mnt/data'", true, 'quoted /mnt/data'],
	['+/Users/me/Documents', true, 'POSIX user dir'],
	["+  const p = '/opt/tools'", true, 'quoted /opt'],
	['+  x: y = z // comment with slash', false, 'trailing comment slash'],
	["+  url: 'https://x/y'", false, 'URL inside quotes'],
	['+cd /home/my-user', true, 'hyphen in POSIX component name'],
	['+/Home/user', true, 'POSIX dir case-insensitive'],
	['+/bin/ls', true, '/bin whitelisted'],
	['+/lib/x86_64-linux-gnu/libc.so.6', true, '/lib + hyphen/dot component'],
	['+/run/user/1000', true, '/run whitelisted'],
	['+  net use \\\\server\\share', false, 'UNC path with double backslash'],
	['+  const s = "\\\\r\\\\n";', false, 'double-backslash escape'],
	['+  /\\\\u2502/', false, 'backslash-u escape not UNC'],
	['+import x from "../lib/foo.js"', false, 'relative import not absolute'],
	['+  git -C ..\\..\\outside status', false, 'backslash relative traversal'],
	['+const p = "./bin/sh";', false, 'dot-relative path'],
	// glob 模式豁免:通配符相邻 '/' 或另一通配符才放行,真路径仍须拦
	['+\t\t"**/lib/**",', false, 'oxlint ignorePatterns 双星 glob'],
	['+"**/node_modules/**"', false, 'glob 前缀双星'],
	['+  ignorePatterns: ["**/dist/**", "**/docs/**"],', false, '同行多个 glob'],
	['+"**/*.mjs"', false, 'glob 后缀单星'],
	['+  files: ["src/**/*.{ts,tsx}"]', false, 'glob 花括号 + 中缀星'],
	['+  "/lib/*.ts"', false, 'POSIX glob 单星后缀'],
	['+/etc/[a-z]*', false, 'POSIX glob 字符类'],
	['+  "**/data/**"', false, 'glob data 目录名'],
	['+"**/usr/**"', false, 'glob usr 目录名'],
	['+  path: "/home/*"', false, '真实目录 + glob 通配'],
	['+cd /etc/passwd && rm **/*.log', true, '同行 glob 不掩盖真绝对路径'],
	['+  "/home/user/**"', false, '真实用户目录下的 glob 模式'],
	['+fix: 修复 /home/user 的问题?', true, '中文问号紧邻路径仍须拦'],
	['+"**/lib/**", // see /etc/passwd', true, 'glob 不掩盖同行真路径'],
]

let failed = 0
for (const [line, expected, label] of cases) {
	const got = isOffendingAddedLine(line)
	const mk = got === expected ? 'PASS' : 'FAIL'
	if (got !== expected) failed += 1
	console.log(`${mk}  expect=${expected}  got=${got}  :: ${label} :: ${line}`)
}
const total = failed + skipFailed
console.log(total === 0 ? '\nALL PASS' : `\n${total} FAILED`)
process.exit(total === 0 ? 0 : 1)
