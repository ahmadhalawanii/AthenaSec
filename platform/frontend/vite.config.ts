import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')

  // Where the AthenaSec backend runs during development. Requests to /api
  // are forwarded there, so the browser treats them as the same site and
  // the backend's session cookie works.
  const backend = env.ATHENASEC_BACKEND_URL || 'http://localhost:8000'

  // Opening the site by a Tailscale name (myserver.tailnet.ts.net) as well as by IP
  const allowedHosts = ['.ts.net']

  return {
    plugins: [react()],
    server: {
      allowedHosts,
      proxy: {
        '/api': { target: backend, changeOrigin: true },
      },
    },
    preview: {
      allowedHosts,
      proxy: {
        '/api': { target: backend, changeOrigin: true },
      },
    },
  }
})
