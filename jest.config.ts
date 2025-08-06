import type { Config } from '@jest/types';

const config: Config.InitialOptions = {
  coverageThreshold: {
    global: {
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
  coverageReporters: ['json-summary'],
  testTimeout: 10000,
  verbose: true,
  projects: [
    {
      setupFiles: ['jest-localstorage-mock'],
      preset: 'ts-jest',
      displayName: 'node',
      testEnvironment: 'node',
    },
    {
      setupFiles: ['jest-localstorage-mock'],
      preset: 'ts-jest',
      displayName: 'jsdom',
      testEnvironment: './jsdom-polyfills.environment.ts',
    },
  ],
};

export default config;
