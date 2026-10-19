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

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    https: cert && key ? { cert: readFileSync(cert), key: readFileSync(key) } : undefined,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
})
