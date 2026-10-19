import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Tests use mocked fetch and do not load the application's TLS/proxy settings.
export default defineConfig({
  plugins: [react()],
  // Bound DOM worker concurrency for predictable memory/CPU use in WSL and CI.
  test: { environment: 'jsdom', clearMocks: true, restoreMocks: true, maxWorkers: 2 },
})
