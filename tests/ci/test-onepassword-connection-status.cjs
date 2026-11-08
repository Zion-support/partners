'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync, mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');
const { spawnSync } = require('node:child_process');

// Any future test that forgets dependency injection must remain offline.
globalThis.fetch = async () => { throw new Error('Real network is prohibited in this test suite'); };

const { checkConnection, MAX_RESPONSE_BYTES, MESSAGES } = require('../../scripts/check-onepassword-connection-status.cjs');

const CANARY = 'SYNTHETIC_PRIVATE_DATA_DO_NOT_LOG';
const KEY = 'synthetic-test-key-not-a-credential';
const ID = 'ca_synthetic_test';
const base = () => ({ id: ID, toolkit: { slug: '_1password' }, status: 'ACTIVE', state: { val: { token: CANARY } }, data: { items: [CANARY] } });
const response = (body, status = 200, type = 'application/json') => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': type } });

function privateResult(result) {
  assert.ok(Object.values(MESSAGES).includes(result.message));
  assert.deepEqual(Object.keys(result).sort(), ['message', 'ok']);
  assert.equal(JSON.stringify(result).includes(CANARY), false);
  assert.equal(JSON.stringify(result).includes(KEY), false);
  assert.equal(JSON.stringify(result).includes(ID), false);
}

test('only one fixed-host metadata GET, no provider tools or request body', async () => {
  let calls = 0;
  const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async (url, options) => {
    calls++;
    assert.equal(url, 'https://backend.composio.dev/api/v3/connected_accounts/' + ID);
    assert.equal(options.method, 'GET');
    assert.equal(options.body, undefined);
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers['x-api-key'], KEY);
    assert.equal(options.headers.accept, 'application/json');
    assert.ok(options.signal instanceof AbortSignal);
    return response(base());
  } });
  assert.equal(calls, 1);
  assert.deepEqual(result, { ok: true, message: MESSAGES.success });
  privateResult(result);
});

for (const apiKey of [undefined, '', '   ']) {
  test('missing key makes zero requests: ' + JSON.stringify(apiKey), async () => {
    let calls = 0;
    const result = await checkConnection({ apiKey, connectionId: ID, fetchImpl: () => { calls++; throw new Error(CANARY); } });
    assert.equal(calls, 0);
    assert.equal(result.ok, false);
    assert.equal(result.message, MESSAGES.missingKey);
    privateResult(result);
  });
}
for (const connectionId of [undefined, '', '../escape', 'ca_valid?token=' + CANARY, 'ca_\n' + CANARY, 'https://other.example', 'x'.repeat(129)]) {
  test('invalid connection identifier makes zero requests: ' + JSON.stringify(connectionId), async () => {
    let calls = 0;
    const result = await checkConnection({ apiKey: KEY, connectionId, fetchImpl: () => { calls++; throw new Error(CANARY); } });
    assert.equal(calls, 0);
    assert.equal(result.ok, false);
    assert.equal(result.message, MESSAGES.missingConnection);
    privateResult(result);
  });
}
for (const status of [301, 302, 400, 401, 403, 404, 429, 500]) {
  test('HTTP ' + status + ' fails without reading response or logging details', async () => {
    const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async () => ({
      status,
      get body() { throw new Error('Body must not be read: ' + CANARY); },
      get headers() { throw new Error('Headers must not be read: ' + CANARY); },
    }) });
    assert.equal(result.ok, false);
    privateResult(result);
  });
}
for (const [name, body] of [
  ['wrong account', { ...base(), id: 'ca_other' }],
  ['wrong toolkit', { ...base(), toolkit: { slug: 'gmail' } }],
  ['inactive', { ...base(), status: 'EXPIRED' }],
  ['untrusted status text', { ...base(), status: CANARY }],
  ['disabled account', { ...base(), is_disabled: true }],
  ['disabled auth config', { ...base(), auth_config: { is_disabled: true } }],
  ['missing status', { id: ID, toolkit: { slug: '_1password' } }],
  ['array', [base()]],
  ['null', null],
  ['malformed JSON', '{' + CANARY],
  ['overlong body', JSON.stringify({ ...base(), data: CANARY.repeat(MAX_RESPONSE_BYTES) })],
]) {
  test('rejects ' + name + ' without disclosing response', async () => {
    const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async () => response(body) });
    assert.equal(result.ok, false);
    privateResult(result);
  });
}
test('rejects non-JSON response before reading body', async () => {
  const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async () => ({
    status: 200,
    headers: new Headers({ 'content-type': 'text/html' }),
    get body() { throw new Error(CANARY); },
  }) });
  assert.equal(result.ok, false);
  assert.equal(result.message, MESSAGES.invalid);
  privateResult(result);
});
test('allows JSON charset without revealing embedded private fields', async () => {
  const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async () => response(base(), 200, 'application/json; charset=utf-8') });
  assert.equal(result.ok, true);
  privateResult(result);
});
for (const error of [new Error(CANARY), new DOMException(CANARY, 'TimeoutError'), new DOMException(CANARY, 'AbortError')]) {
  test('transport exception remains private: ' + error.name, async () => {
    const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async () => { throw error; } });
    assert.equal(result.ok, false);
    assert.equal(result.message, MESSAGES.request);
    privateResult(result);
  });
}
test('body stream errors remain private', async () => {
  const result = await checkConnection({ apiKey: KEY, connectionId: ID, fetchImpl: async () => ({
    status: 200,
    headers: new Headers({ 'content-type': 'application/json' }),
    body: { async *[Symbol.asyncIterator]() { yield Buffer.from('{'); throw new Error(CANARY); } },
  }) });
  assert.equal(result.ok, false);
  privateResult(result);
});

for (const [name, setup, expectedExit, expectedOutput] of [
  ['success', 'return new Response(' + JSON.stringify(JSON.stringify(base())) + ', { headers: { "content-type": "application/json" } });', 0, MESSAGES.success],
  ['remote error', 'throw new Error(' + JSON.stringify(CANARY + KEY + ID) + ');', 1, MESSAGES.request],
]) {
  test('actual CLI stdout/stderr is constant for ' + name + ' with mocked network', () => {
    const dir = mkdtempSync(join(tmpdir(), 'onepassword-privacy-test-'));
    try {
      const hook = join(dir, 'offline.cjs');
      writeFileSync(hook, 'global.fetch = async () => { ' + setup + ' };');
      const result = spawnSync(process.execPath, ['--require', hook, resolve(__dirname, '../../scripts/check-onepassword-connection-status.cjs')], {
        cwd: dir,
        env: { COMPOSIO_API_KEY: KEY, COMPOSIO_1PASSWORD_CONNECTION_ID: ID },
        encoding: 'utf8',
        timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, expectedExit);
      assert.equal(result.stdout + result.stderr, expectedOutput + '\n');
      assert.equal((result.stdout + result.stderr).includes(CANARY), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
test('workflow has no SDK, vault-item execution, generated inline script, or response logging', () => {
  const workflow = readFileSync(resolve(__dirname, '../../.github/workflows/onepassword-sync.yml'), 'utf8');
  const script = readFileSync(resolve(__dirname, '../../scripts/check-onepassword-connection-status.cjs'), 'utf8');
  assert.doesNotMatch(workflow + script, /_1PASSWORD_LIST_ITEMS|tools\.execute|@composio\/core|sync\.mjs|console\.(log|error)|JSON\.stringify/);
  assert.match(workflow, /node --test tests\/ci\/test-onepassword-connection-status\.cjs/);
  assert.match(workflow, /node scripts\/check-onepassword-connection-status\.cjs/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /node-version: 22/);
  assert.match(workflow, /contents: read/);
  assert.doesNotMatch(workflow, /npm install|has_key=true|connection refreshed successfully/);
});

for (const [name, env, message] of [
  ['key', {}, MESSAGES.missingKey],
  ['connection identifier', { COMPOSIO_API_KEY: KEY }, MESSAGES.missingConnection],
]) {
  test('actual CLI fails before any request when missing ' + name, () => {
    const dir = mkdtempSync(join(tmpdir(), 'onepassword-no-network-test-'));
    try {
      const hook = join(dir, 'offline.cjs');
      writeFileSync(hook, 'global.fetch = async () => { process.stderr.write("UNEXPECTED_REQUEST"); throw new Error("Real network is prohibited"); };');
      const result = spawnSync(process.execPath, ['--require', hook, resolve(__dirname, '../../scripts/check-onepassword-connection-status.cjs')], {
        cwd: dir, env, encoding: 'utf8', timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, message + '\n');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
