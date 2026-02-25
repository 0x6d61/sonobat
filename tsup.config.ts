import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  external: ['better-sqlite3'],
  banner: {
    js: '#!/usr/bin/env node',
  },
});
