import type { Config } from '@jest/types';

const config: Config.InitialOptions = {
  coverageThreshold: {
    global: {
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
  preset: 'ts-jest',
  testEnvironment: 'jsdom', // TODO: run tests through both 'node' and 'jsdom'
  verbose: true
};
export default config;
