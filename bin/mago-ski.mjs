#!/usr/bin/env node
import { runCli } from '../src/cli.mjs';

runCli().catch((error) => {
  process.stderr.write(`mago-ski: ${error?.message ?? 'operation failed'}\n`);
  process.exitCode = error?.exitCode ?? 2;
});
