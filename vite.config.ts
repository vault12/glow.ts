import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'unplugin-dts/vite';

import { dependencies } from './package.json';

export default defineConfig({
  build: {
    sourcemap: true,
    lib: {
      entry: resolve(__dirname, 'src/index.ts'), // Main entry point
      formats: ['es', 'cjs'], // ESM and CommonJS
      fileName: (format) => `glow.${format}.js`,
    },
    rollupOptions: {
      // Make sure to externalize deps that shouldn't be bundled
      external: [...Object.keys(dependencies ?? {})],
    },
  },

  plugins: [dts({ bundleTypes: true })],
});
