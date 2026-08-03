import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Any request starting with /api will be proxied to your target URL
      '/api': {
        target: 'https://temant',
        changeOrigin: true,
        secure: true,
        rewrite: (path) => path.replace(/^\/api/, '/Temant-EncryptionManager/demo/api'),
      },
    },
  },
})