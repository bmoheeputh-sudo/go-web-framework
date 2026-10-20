import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'

// Load only explicitly supplied local TLS files; never expose backend OIDC
// configuration through VITE_* or the frontend bundle.
const cert = process.env.DEV_TLS_CERT_FILE
const key = process.env.DEV_TLS_KEY_FILE
if (Boolean(cert) !== Boolean(key)) {
  throw new Error('Set both DEV_TLS_CERT_FILE and DEV_TLS_KEY_FILE for HTTPS')
}

function localPort(name: string, fallback: number): number {
  const raw = process.env[name]
  if (raw === undefined) return fallback
  if (!/^[0-9]+$/.test(raw)) throw new Error(`${name} must be a TCP port`)
  const port = Number(raw)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be a TCP port`)
  }
  return port
}

// Ordinary development retains its existing ports. Rehearsal variables only
// select local listeners; they are not exposed through VITE_* to browser code.
const frontendPort = localPort('AUTH_REHEARSAL_FRONTEND_PORT', 5173)
const backendPort = localPort('AUTH_REHEARSAL_BACKEND_PORT', 8080)

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: frontendPort,
    strictPort: true,
    https: cert && key ? { cert: readFileSync(cert), key: readFileSync(key) } : undefined,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
      },
    },
  },
})
