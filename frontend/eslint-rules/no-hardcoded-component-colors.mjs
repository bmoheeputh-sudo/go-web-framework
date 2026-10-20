const colorValue = /#[\da-f]{3,8}\b|\b(?:rgba?|hsla?)\s*\(|(?<![\w.])(?:red|blue|green|white|black|gray|grey|orange|yellow|purple|pink|cyan|magenta|lime|navy|teal|silver|maroon|olive|aqua|fuchsia)\b/i
const colorProperty = /^(?:color|bgcolor|background(?:Color)?|border(?:Top|Right|Bottom|Left)?Color|fill|stroke)$/i
const semanticValue = /^(?:inherit|initial|unset|revert|transparent|currentcolor|none|divider|primary|secondary|success|error|warning|info|default)$/i

function arbitraryNamedColor(node, value) {
  const property = node.parent
  if (property?.type !== 'Property') return false
  const name = property.key.name || property.key.value
  return colorProperty.test(String(name)) && /^[a-z]+$/i.test(value) && !semanticValue.test(value)
}

function cssNamedColor(value) {
  const declarations = value.matchAll(/\b(?:color|background(?:-color)?|border(?:-[a-z]+)?-color|fill|stroke)\s*:\s*([a-z]+)\s*(?:;|$)/gi)
  return [...declarations].some((match) => !semanticValue.test(match[1]))
}

function isStyleContext(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (parent.type === 'JSXAttribute' && (parent.name.name === 'sx' || parent.name.name === 'style')) return true
    if (parent.type === 'CallExpression' && (
      parent.callee.name === 'styled' || parent.callee.type === 'CallExpression' && parent.callee.callee.name === 'styled'
    )) return true
    if (parent.type === 'TaggedTemplateExpression' && (
      parent.tag.name === 'styled' || parent.tag.type === 'CallExpression' && parent.tag.callee.name === 'styled'
    )) return true
  }
  return false
}

export default {
  meta: {
    type: 'problem',
    docs: { description: 'Require theme colors in component styling' },
    schema: [],
    messages: { themeColor: 'Use a MUI palette token or theme-derived color in component styling.' },
  },
  create(context) {
    function check(node, value) {
      if (isStyleContext(node) && (colorValue.test(value) || arbitraryNamedColor(node, value) || cssNamedColor(value)))
        context.report({ node, messageId: 'themeColor' })
    }
    return {
      Literal(node) { if (typeof node.value === 'string') check(node, node.value) },
      TemplateElement(node) { check(node, node.value.raw) },
    }
  },
}
