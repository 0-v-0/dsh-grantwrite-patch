// 校验 commit-msg 判定逻辑,并比对钩子内嵌共享片段是否过期
import {
	assertSnippetsFresh,
	checkCommitSubject,
	filterCommitLines,
	readHookTemplate,
} from './hook-logic.ts'

console.log(
	'[verify-commit-msg] 用法: node scripts/verify-commit-msg.ts(校验 commit-msg 钩子判定逻辑,先运行 node scripts/install-hooks.ts 生成钩子)',
)

// 钩子缺失即未安装
let template
try {
	template = readHookTemplate('commit-msg', 'verify-commit-msg')
} catch (err) {
	console.error(err.message)
	process.exit(1)
}
assertSnippetsFresh(template, ['constants', 'commitMsg'], 'verify-commit-msg', 'commit-msg')

const cases = [
	['feat(cmem): add hybrid query', true, 'feat with scope'],
	['fix(matcher): sandbox regex in worker', true, 'fix with scope'],
	['refactor: optimization round 3', true, 'refactor'],
	['chore: format', true, 'chore'],
	['docs: update', true, 'docs'],
	['perf: cache http refs', true, 'perf'],
	['test: cover redirect revalidation', true, 'test'],
	['build: bump oxlint', true, 'build'],
	['ci: cache pnpm store', true, 'ci'],
	['style: semicolons', true, 'style'],
	['revert: revert cmem_query', true, 'revert'],
	['feat!: breaking change', true, 'breaking'],
	['feat(cmem)!: breaking with scope', true, 'breaking+scope'],
	['  feat: leading whitespace', false, 'leading space not trimmed'],
	['fix:no-space-after-colon', false, 'missing space after colon'],
	['feat:\t', false, 'description starts with tab'],
	['feat:   spaces only', false, 'description starts with spaces'],
	['feat:', false, 'empty description'],
	['random text', false, 'non-conventional'],
	['', false, 'empty message'],
	['FIX: uppercase type', false, 'uppercase type'],
	['feat(scope(extra)): nested parens', false, 'nested scope parens'],
	['chore: bump\n- detail one\n- detail two', true, 'body lines ok'],
	[
		'# Please enter the commit message\nfeat: real subject\n# branch is up to date',
		true,
		'git comments stripped',
	],
	['fixup! refactor: code optimization round', true, 'git fixup prefix'],
	['squash! feat(cmem): add hybrid query', true, 'git squash prefix'],
	['amend! chore: format', true, 'git amend prefix'],
	['fixup! not-a-conventional-target', false, 'fixup 目标非常规格式'],
	['squash! random text', false, 'squash 目标非常规格式'],
	['amend! no-colon-target', false, 'amend 目标非常规格式'],
	['fixup! abcdef1', true, 'fixup 目标为 7 位短哈希'],
	['squash! abcdef12', true, 'squash 目标为 8 位短哈希'],
	['amend! abcdef1234', true, 'amend 目标为 10 位短哈希'],
	['fixup! ABCDEF123', false, '大写十六进制哈希不匹配'],
	['fixup! abc', false, '短哈希不足 7 位'],
	['fixup! abcdef123! trailing', false, '哈希后跟多余文本'],
	['fixup! ', false, 'fixup 空 target'],
	['squash! 12345678: not conventional', false, '哈希+冒号混合 target'],
	['feat: add loader for D:\\ai\\mnemon.exe', false, 'drive path in subject'],
	['chore: bump\n- fix path C:\\Users\\me\\file', false, 'drive path in body'],
	['feat: refactor /home/user/code', false, 'posix path in subject'],
	['fix: use /usr/local/bin script', false, 'posix /usr in subject'],
	['feat: use ./scripts/run.mjs', true, 'relative path ok'],
	['feat: use ~/config.yaml', true, 'home placeholder ok'],
	['fixup! refactor: clean D:\\tmp\\cache', false, 'fixup prefix still blocks abs path'],
	['doc: https://example.com/x', false, 'scheme still not a type'],
	['feat: url https://example.com/x ok', true, 'URL scheme not abs path'],
	['feat: mount \\server\\share', true, 'UNC path in subject allowed'],
	['chore: ignore **/lib/** and **/dist/**', true, 'glob 模式不算绝对路径'],
	['fix: 忽略 **/usr/** 目录', true, 'glob 模式(中文描述)不算绝对路径'],
	['fix: ignore **/lib/** but see /etc/passwd', false, '同行 glob 不掩盖真绝对路径'],
	['fix: /home/user 路径有中文标点,处理?', false, '中文问号紧邻路径仍须拦'],
]

let failed = 0
for (const [raw, expected, label] of cases) {
	const got = checkCommitSubject(filterCommitLines(raw))
	const ok = got.pass
	const mk = ok === expected ? 'PASS' : 'FAIL'
	if (ok !== expected) failed += 1
	const detail = ok ? '' : `  [${got.kind}: ${got.hit}]`
	console.log(
		`${mk}  expect=${expected}  got=${ok}  :: ${label} :: ${JSON.stringify(raw)}` + detail,
	)
}
console.log(failed === 0 ? '\nALL PASS' : `\n${failed} FAILED`)
process.exit(failed === 0 ? 0 : 1)
