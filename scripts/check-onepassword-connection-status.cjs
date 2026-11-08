'use strict';

// Metadata-only diagnostic. Never execute a provider tool, refresh a connection,
// log response bodies, or propagate remote exception messages to CI output.
const MAX_RESPONSE_BYTES = 64 * 1024;
const MESSAGES = Object.freeze({
  missingKey: 'COMPOSIO_API_KEY is unavailable. No request was made.',
  missingConnection: 'COMPOSIO_1PASSWORD_CONNECTION_ID is unavailable or malformed. No request was made.',
  authentication: 'Composio rejected the diagnostic request. No response details are logged.',
  request: 'Composio connection metadata could not be checked. No response details are logged.',
  invalid: 'Composio returned invalid connection metadata. No response details are logged.',
  mismatch: 'The configured connection does not identify an enabled, active 1Password account.',
  success: 'Composio reports the configured 1Password connection as ACTIVE. No vault items were read or synchronized.',
});

async function readSmallJson(response) {
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > MAX_RESPONSE_BYTES) throw new Error('Response limit exceeded');
    chunks.push(Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function checkConnection({ apiKey, connectionId, fetchImpl = globalThis.fetch }) {
  if (typeof apiKey !== 'string' || apiKey.trim() === '') {
    return { ok: false, message: MESSAGES.missingKey };
  }
  if (typeof connectionId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(connectionId)) {
    return { ok: false, message: MESSAGES.missingConnection };
  }

  try {
    const response = await fetchImpl(
      'https://backend.composio.dev/api/v3/connected_accounts/' + encodeURIComponent(connectionId),
      {
        method: 'GET',
        headers: { 'x-api-key': apiKey, accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
      },
    );
    if (response.status === 401 || response.status === 403) {
      return { ok: false, message: MESSAGES.authentication };
    }
    if (response.status !== 200) return { ok: false, message: MESSAGES.request };
    if (!/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get('content-type') || '')) {
      return { ok: false, message: MESSAGES.invalid };
    }
    const account = await readSmallJson(response);
    if (!account || typeof account !== 'object' || Array.isArray(account)) {
      return { ok: false, message: MESSAGES.invalid };
    }
    if (
      account.id !== connectionId ||
      account.toolkit?.slug !== '_1password' ||
      account.status !== 'ACTIVE' ||
      account.is_disabled === true ||
      account.auth_config?.is_disabled === true
    ) {
      return { ok: false, message: MESSAGES.mismatch };
    }
    return { ok: true, message: MESSAGES.success };
  } catch {
    // Remote bodies, request URLs, account IDs and credentials never reach logs.
    return { ok: false, message: MESSAGES.request };
  }
}

async function main() {
  const result = await checkConnection({
    apiKey: process.env.COMPOSIO_API_KEY,
    connectionId: process.env.COMPOSIO_1PASSWORD_CONNECTION_ID,
  });
  const output = result.ok ? process.stdout : process.stderr;
  output.write(result.message + '\n');
  process.exitCode = result.ok ? 0 : 1;
}

if (require.main === module) main();
module.exports = { checkConnection, MAX_RESPONSE_BYTES, MESSAGES };
