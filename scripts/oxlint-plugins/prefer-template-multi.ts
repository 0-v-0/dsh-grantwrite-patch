/**
 * Custom prefer-template variant: reports only when a `+` chain joins 2+ parts;
 * single-`+` joins (e.g. `'a' + b`) are exempt. Autofix rewrites chains to
 * template literals.
 *
 * Why: oxlint/eslint prefer-template has no options and also reports trivial
 * single-segment joins. This rule raises the threshold to 2, requiring only
 * chained concatenation to become a template literal.
 *
 * Notes:
 * - The built-in "prefer-template" must be off, otherwise single-`+` cases are
 *   double-reported;
 * - pure string-literal joins (`'a' + 'b'`) follow ESLint semantics and are
 *   not reported (that is no-useless-concat's job);
 * - joins of variables only (`a + b`) cannot be statically confirmed as
 *   strings, so they are not reported;
 * - the plugin name prefer-template-multi is not an oxlint reserved name, so
 *   jsPlugins loads it directly.
 */

// oxlint JS plugins run under Node type-stripping (no enum/namespace); the AST
// is ESTree/oxc-compatible nodes, described here by the minimal structural
// types this rule touches.
interface OxNode {
	type: string
	operator?: string
	value?: unknown
	left?: OxNode
	right?: OxNode
	parent?: OxNode
}

interface RuleContext {
	sourceCode: {
		getText: (node: OxNode) => string
	}
	report: (problem: unknown) => void
}

const rule = {
	create(context: RuleContext) {
		return {
			BinaryExpression(node: OxNode) {
				if (node.operator !== '+') {
					return
				}
				// Report only at the outermost `+`: skip when the parent is also
				// a `+`, so a chain is reported once instead of per-operator.
				if (
					node.parent &&
					node.parent.type === 'BinaryExpression' &&
					node.parent.operator === '+'
				) {
					return
				}
				if (!isStringConcat(node)) {
					return
				}
				const count = countPlus(node)
				if (count < 2) {
					return
				}
				context.report({
					data: { count },
					fix(fixer: { replaceText: (a: unknown, b: string) => unknown }) {
						const parts: string[] = []
						collectParts(context.sourceCode, node, parts)
						return fixer.replaceText(node, `\`${parts.join('')}\``)
					},
					messageId: 'preferTemplate',
					node,
				})
			},
		}
	},
	meta: {
		docs: {
			description:
				'Require template literals for multi-part string concatenations (2+ `+`), exempting single `+` joins.',
		},
		fixable: 'code',
		messages: {
			preferTemplate:
				'Use a template literal instead of concatenating {{count}} parts with `+`.',
		},
		type: 'suggestion',
	},
}

// A tree is a string concatenation when any leaf is a string or template literal.
function isStringConcat(node: OxNode): boolean {
	if (isStringLeaf(node)) {
		return true
	}
	if (node.type === 'BinaryExpression' && node.left && node.right) {
		return isStringConcat(node.left) || isStringConcat(node.right)
	}
	return false
}

// Flatten the `+` chain: string leaves are escaped as template text, other
// leaves are wrapped in ${...}.
function collectParts(sourceCode: RuleContext['sourceCode'], node: OxNode, parts: string[]): void {
	if (node.type === 'BinaryExpression' && node.left && node.right) {
		if (node.operator === '+') {
			collectParts(sourceCode, node.left, parts)
			collectParts(sourceCode, node.right, parts)
			return
		}
		// A non-`+` subexpression (e.g. `a * b`) is embedded as a whole.
		parts.push(`\${${sourceCode.getText(node)}}`)
		return
	}
	if (isStringLeaf(node) && typeof node.value === 'string') {
		parts.push(escapeTemplateText(node.value))
		return
	}
	parts.push(`\${${sourceCode.getText(node)}}`)
}

function isStringLeaf(node: OxNode): boolean {
	if (node.type === 'Literal' && typeof node.value === 'string') {
		return true
	}
	if (node.type === 'StringLiteral') {
		return true
	}
	return false
}

// Escape a string value as template text, in order:
// \ -> \\, \r\n -> escape sequences, ` -> \`, ${ -> \${.
function escapeTemplateText(value: string): string {
	return value
		.replaceAll('\\', '\\\\')
		.replaceAll('\r', '\\r')
		.replaceAll('\n', '\\n')
		.replaceAll('`', '\\`')
		.replaceAll('${', '\\${')
}

// Count the `+` operators in the whole expression tree (nested included).
function countPlus(node: OxNode): number {
	if (node.type !== 'BinaryExpression' || node.operator !== '+') {
		return 0
	}
	return 1 + countPlus(node.left ?? { type: '' }) + countPlus(node.right ?? { type: '' })
}

export default {
	meta: { name: 'prefer-template-multi' },
	rules: { 'prefer-template': rule },
}
