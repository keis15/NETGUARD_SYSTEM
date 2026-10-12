import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `npm run dev` serves the UI on :5173 and proxies /api to the backend on :8600.
export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 900 }, // local app: one bundle is fine
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8600' },
  },
})
