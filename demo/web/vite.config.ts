import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// This app is one of several Temant package demos hosted under the same domain (see
// demo/README.md), each mounted at its own subpath — e.g. /encryption-manager/ — rather than
// at the domain root. `base` keeps every asset URL and API call this app makes relative to
// that subpath, so it works unmodified regardless of where it's aliased in production.
const base = '/encryption-manager/'

// https://vite.dev/config/
export default defineConfig({
  base,
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // The PHP API lives in demo/api and is served separately in dev (see demo/README.md).
      // Proxying keeps the browser's view of everything same-origin, so session cookies work
      // without any CORS configuration.
      [`${base}api`]: {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // `php -S -t demo/api` treats demo/api as its own docroot, so <base>api/meta.php on
        // the dev server needs to become /meta.php once forwarded. In production this mapping
        // is the same shape as an Apache Alias "<base>api" -> "demo/api" (see demo/README.md).
        rewrite: (path) => path.replace(new RegExp(`^${base}api`), ''),
      },
    },
  },
})
