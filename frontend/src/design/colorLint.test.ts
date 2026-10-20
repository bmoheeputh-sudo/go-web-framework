import { expect, it } from 'vitest'
import { ESLint } from 'eslint'

const lint = new ESLint()
const filename = 'src/pages/ColorProbe.tsx'
async function designErrors(source: string) {
  const [result] = await lint.lintText(source, { filePath: filename })
  return result.messages.filter((message) => message.ruleId === 'designSystem/no-hardcoded-component-colors')
}

it('rejects literal hex, functional, and arbitrary named component colors', async () => {
  for (const value of ['#123456', 'rgb(1, 2, 3)', 'hsl(200, 50%, 50%)', 'rebeccapurple']) {
    expect(await designErrors(`export default function Probe() { return <div style={{ color: '${value}' }} /> }`)).toHaveLength(1)
  }
  expect(await designErrors("export default function Probe() { return <div sx={{ bgcolor: '#abc' }} /> }"))
    .toHaveLength(1)
  expect(await designErrors("const Probe = styled('div')`color: rebeccapurple;`"))
    .toHaveLength(1)
})

it('allows palette tokens and unrelated data values', async () => {
  expect(await designErrors("export default function Probe() { const id = '#123456'; return <div data-id={id} style={{ color: 'primary.main', borderColor: 'divider' }} /> }"))
    .toHaveLength(0)
})
