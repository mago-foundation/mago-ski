#!/usr/bin/env node
// Checks out the pull request's base revision directly into RUNNER_TEMP for check/action.yml.
// Runs outside GITHUB_WORKSPACE without persisting credentials.
import { execFile } from 'node:child_process';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { isMainModule } from '../../src/main-module.ts';
import { escapeAnnotation } from './run.ts';

const execFileAsync = promisify(execFile);

const GIT_HARDENING_FLAGS = [
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.fsmonitor=false',
  '-c', 'filter.lfs.process=',
  '-c', 'filter.lfs.smudge=',
  '-c', 'filter.lfs.required=false',
] as const;

const GIT_ENV_KEYS_TO_DELETE = [
  'MAGO_TOKEN',
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_PARAMETERS',
] as const;

export interface BaseCheckoutOptions {
  repoUrl: string;
  baseSha: string;
  destination: string;
  token?: string;
  authScope?: string;
}

/** Validates that a pull request base revision is a full 40- or 64-character lowercase hex commit SHA. */
export function validateBaseSha(sha: string | undefined): string {
  if (!sha || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(sha)) {
    throw new Error('invalid pull request base revision');
  }
  return sha;
}

/** Builds and validates the HTTPS repository URL and HTTP auth scope from GitHub environment values. */
export function buildBaseRepoUrl(
  serverUrl: string | undefined,
  repository: string | undefined,
): { repoUrl: string; authScope: string } {
  if (!serverUrl) throw new Error('invalid GitHub server URL');
  let parsed: URL;
  try {
    parsed = new URL(serverUrl);
  } catch {
    throw new Error('invalid GitHub server URL');
  }
  if (
    parsed.protocol !== 'https:'
    || !parsed.hostname
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.search !== ''
    || parsed.hash !== ''
  ) {
    throw new Error('invalid GitHub server URL');
  }

  if (!repository || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)) {
    throw new Error('invalid GitHub repository');
  }
  const [owner, repo] = repository.split('/') as [string, string];
  for (const segment of [owner, repo]) {
    if (segment === '.' || segment === '..' || segment.startsWith('-')) {
      throw new Error('invalid GitHub repository');
    }
  }

  const basePath = parsed.pathname.replace(/\/+$/u, '');
  const authScope = `${parsed.origin}${basePath}`;
  const repoUrl = `${authScope}/${owner}/${repo}.git`;
  return { repoUrl, authScope };
}

function buildSanitizedGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of GIT_ENV_KEYS_TO_DELETE) {
    delete env[key];
  }
  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_CONFIG_KEY_') || key.startsWith('GIT_CONFIG_VALUE_')) {
      delete env[key];
    }
  }
  env.GIT_TERMINAL_PROMPT = '0';
  return env;
}

function sanitizeError(error: unknown, token?: string): Error {
  const message = error instanceof Error ? error.message : String(error);
  if (!token) return error instanceof Error ? error : new Error(message);
  const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
  const scrubbed = message.split(token).join('[REDACTED]').split(basic).join('[REDACTED]');
  return new Error(scrubbed);
}

/** Fetches and checks out the validated base commit into a clean directory without persisting credentials. */
export async function checkoutBaseRevision(options: BaseCheckoutOptions): Promise<string> {
  const baseSha = validateBaseSha(options.baseSha);
  const dest = path.resolve(options.destination);
  const baseEnv = buildSanitizedGitEnv();

  await rm(dest, { recursive: true, force: true });
  await mkdir(dest, { mode: 0o700 });

  try {
    await execFileAsync('git', ['-C', dest, 'init', '--quiet'], { env: baseEnv });

    const fetchEnv: NodeJS.ProcessEnv = { ...baseEnv };
    if (options.token && options.authScope) {
      fetchEnv.GIT_CONFIG_COUNT = '1';
      fetchEnv.GIT_CONFIG_KEY_0 = `http.${options.authScope}/.extraheader`;
      fetchEnv.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${options.token}`).toString('base64')}`;
    }

    await execFileAsync(
      'git',
      ['-C', dest, '-c', 'protocol.version=2', ...GIT_HARDENING_FLAGS, 'fetch', '--quiet', '--no-tags', '--depth=1', options.repoUrl, baseSha],
      { env: fetchEnv },
    );

    await execFileAsync(
      'git',
      ['-C', dest, ...GIT_HARDENING_FLAGS, 'checkout', '--quiet', '--detach', 'FETCH_HEAD'],
      { env: baseEnv },
    );

    const { stdout } = await execFileAsync('git', ['-C', dest, 'rev-parse', '--verify', 'HEAD'], { env: baseEnv });
    if (stdout.trim() !== baseSha) {
      throw new Error('the base checkout is not at the base revision');
    }

    return dest;
  } catch (error) {
    await rm(dest, { recursive: true, force: true }).catch(() => undefined);
    throw sanitizeError(error, options.token);
  }
}

async function main(): Promise<void> {
  const runnerTemp = process.env.RUNNER_TEMP;
  if (!runnerTemp) throw new Error('RUNNER_TEMP is required');
  const destination = path.join(path.resolve(runnerTemp), 'mago-ski-check-base');
  const { repoUrl, authScope } = buildBaseRepoUrl(process.env.GITHUB_SERVER_URL, process.env.GITHUB_REPOSITORY);
  await checkoutBaseRevision({
    repoUrl,
    authScope,
    baseSha: process.env.MAGO_BASE_SHA ?? '',
    destination,
    ...(process.env.MAGO_TOKEN ? { token: process.env.MAGO_TOKEN } : {}),
  });
}

if (isMainModule(import.meta.url)) {
  main().catch((error: unknown) => {
    const message = sanitizeError(error, process.env.MAGO_TOKEN).message;
    process.stdout.write(`::error title=mago-ski skill check::${escapeAnnotation(message)}\n`);
    process.exitCode = 2;
  });
}
