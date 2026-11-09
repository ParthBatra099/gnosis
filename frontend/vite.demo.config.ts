import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Only explicit demo commands select this configuration. Normal vite.config is unchanged.
export default defineConfig(({ command }) => {
  let https;
  if (command === 'serve') {
    const key = process.env.GNOSIS_DEMO_TLS_KEY;
    const cert = process.env.GNOSIS_DEMO_TLS_CERT;
    if (!key || !cert) throw new Error('Explicit local HTTPS certificate and key paths are required.');
    https = { key: readFileSync(key), cert: readFileSync(cert) };
  }
  return {
    plugins: [react()],
    server: { host: '127.0.0.1', port: 5173, strictPort: true, https },
    preview: { host: '127.0.0.1', port: 5173, strictPort: true, https },
    build: { outDir: 'dist-demo', rollupOptions: { input: resolve(import.meta.dirname, 'demo.html') } },
  };
});
