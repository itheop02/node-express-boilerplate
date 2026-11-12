'use strict';
const assert = require('node:assert/strict');
const { spawn, fork, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const sharedRoot = path.resolve(__dirname, '../..');
const privacyRoot = path.join(__dirname, 'privacy-lib');
const files = [path.join(privacyRoot, 'gdpr-router.cjs'),
  ...fs.readdirSync(path.join(privacyRoot, 'gdpr')).filter(file => file.endsWith('.rego')).map(file => path.join(privacyRoot, 'gdpr', file))];
const hashes = () => files.map(file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'));
const before = hashes();
let checks = 0;
const outcomes = [];
async function check(label, action) {
  try { await action(); checks++; outcomes.push({ name: label, passed: true }); console.log('PASS ' + label); }
  catch (error) { outcomes.push({ name: label, passed: false, error: error.message }); throw error; }
}
async function main() {
  const reservation = net.createServer().listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const opa = spawn(process.env.OPA_BINARY || 'opa', ['run', '--server', '--addr', '127.0.0.1:' + port,
    path.join(privacyRoot, 'gdpr')], { stdio: 'ignore', windowsHide: true });
  let backend;
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try { ready = (await fetch('http://127.0.0.1:' + port + '/health')).ok; if (ready) break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(ready, 'OPA did not start');
    backend = fork(path.join(__dirname, 'start.js'), [], {
      env: { ...process.env, PORT: '0', OPA_QUERY_URL: 'http://127.0.0.1:' + port + '/v1/query',

        MONGOMS_DOWNLOAD_IGNORE_MISSING_HEADER: 'true' },
      stdio: ['ignore', 'inherit', 'inherit', 'ipc'], windowsHide: true,
    });
    const [message] = await Promise.race([once(backend, 'message'),
      once(backend, 'exit').then(([code]) => { throw new Error('Backend stopped: ' + code); })]);
    const base = 'http://127.0.0.1:' + message.port;
    let token, user;
    async function request(method, route, body, authenticated = true) {
      const response = await fetch(base + route, {
        method, headers: { 'Content-Type': 'application/json',
          ...(authenticated && token ? { Authorization: 'Bearer ' + token } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() };
    }
    await check('unauthenticated GDPR request is rejected', async () => {
      assert.equal((await request('POST', '/v1/gdpr/consent', {}, false)).status, 401);
    });
    const email = 'privacy-' + Date.now() + '@example.com';
    await check('register real application user', async () => {
      const r = await request('POST', '/v1/auth/register', { name: 'GDPR Integration User', email, password: 'Integration123' }, false);
      assert.equal(r.status, 201, JSON.stringify(r.body)); user = r.body.user;
    });
    await check('login through original authentication route', async () => {
      const r = await request('POST', '/v1/auth/login', { email, password: 'Integration123' }, false);
      assert.equal(r.status, 200, JSON.stringify(r.body)); token = r.body.tokens.access.token;
    });
    await check('missing consent rejects processing', async () => {
      const r = await request('POST', '/v1/gdpr/consent', {});
      assert.equal(r.status, 200); assert.equal(r.body, false);
    });
    await check('persist consent in MongoDB', async () => {
      const r = await request('PATCH', '/v1/gdpr/consent', { value: 'yes', withdrawn: false });
      assert.equal(r.status, 200); assert.equal(r.body.value, 'yes');
    });
    for (const policy of ['consent', 'lawful']) {
      await check(policy + ' accepts stored consent', async () => {
        const r = await request('POST', '/v1/gdpr/' + policy, {});
        assert.equal(r.status, 200); assert.equal(r.body, true);
      });
    }
    await check('access returns authenticated user field metadata without credentials', async () => {
      const r = await request('POST', '/v1/gdpr/access', {});
      assert.equal(r.status, 200); assert.equal(r.body.request.validated, true);
      const text = JSON.stringify(r.body);
      const download = JSON.parse(r.body.download.content);
      assert.equal(download.user_id, user.id);
      assert.deepEqual(download.data_collected_from_user.map(item => item.field).sort(), ['email', 'name']);
      assert.ok(text.includes(user.id));
      assert.equal(text.includes('Integration123'), false); assert.equal(text.includes('"password"'), false);
    });
    await check('portability returns actual user in two export formats', async () => {
      const r = await request('POST', '/v1/gdpr/portability', {});
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'accept');
      assert.equal(r.body.actions.downloads.length, 2);
      assert.ok(JSON.stringify(r.body.actions.downloads).includes(email));
    });
    await check('information reports the logged-in user context', async () => {
      const r = await request('POST', '/v1/gdpr/information', {});
      assert.equal(r.status, 200); assert.equal(r.body.consent_valid, true);
      assert.equal(r.body.lawful_processing, true);
    });
    await check('rectification returns a name update plan for this user', async () => {
      const r = await request('POST', '/v1/gdpr/rectification', { updates: { name: 'Updated User' } });
      assert.equal(r.status, 200); assert.equal(r.body.request.validated, true);
      assert.ok(r.body.db_update_plan.some(step => step.user_id === user.id && step.field === 'name' && step.new_value === 'Updated User'));
    });
    await check('erasure respects configured retention exception', async () => {
      const r = await request('POST', '/v1/gdpr/erasure', { fields: ['email'] });
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'reject');
      assert.ok(r.body.justification.some(item => item.includes('legal obligation')));
      assert.equal(r.body.actions.delete, undefined);
    });
    await check('restriction returns a processing restriction plan', async () => {
      const r = await request('POST', '/v1/gdpr/restriction', {});
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'accept');
      assert.equal(r.body.actions.stop_processing.target_user_id, user.id);
    });
    await check('marketing objection returns a stop-processing plan', async () => {
      const r = await request('POST', '/v1/gdpr/objection', { reason: 'marketing' });
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'accept');
      assert.equal(r.body.actions.stop_processing.target_user_id, user.id);
    });
    await check('complaint returns a forward plan without sending', async () => {
      const r = await request('POST', '/v1/gdpr/complaint', {
        authority_id: 'cy-0000', description: 'Integration test complaint; do not send.',
      });
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'accept');
      assert.equal(r.body.actions.forward.authority.id, 'cy-0000');
    });
    await check('normal user cannot assess a breach', async () => {
      assert.equal((await request('POST', '/v1/gdpr/breach', { incident_id: 'integration-incident' })).status, 403);
    });
    await check('second real user has independent consent and exports', async () => {
      const otherEmail = 'other-' + Date.now() + '@example.com';
      const r = await request('POST', '/v1/auth/register', {
        name: 'Other User', email: otherEmail, password: 'Integration456',
      }, false);
      assert.equal(r.status, 201);
      const savedToken = token; token = r.body.tokens.access.token;
      try {
        const consent = await request('POST', '/v1/gdpr/consent', {});
        assert.equal(consent.body, false);
        const access = await request('POST', '/v1/gdpr/access', {});
        assert.equal(JSON.parse(access.body.download.content).user_id, r.body.user.id);
        assert.equal(JSON.stringify(access.body).includes(user.id), false);
      } finally { token = savedToken; }
    });
    await check('withdraw consent', async () => {
      const r = await request('PATCH', '/v1/gdpr/consent', { value: 'yes', withdrawn: true });
      assert.equal(r.status, 200); assert.equal(r.body.withdrawn, true);
    });
    for (const policy of ['consent', 'lawful', 'portability']) {
      await check(policy + ' rejects after withdrawal', async () => {
        const r = await request('POST', '/v1/gdpr/' + policy, {});
        assert.equal(r.status, 200);
        assert.deepEqual(policy === 'portability' ? r.body.decision : r.body, policy === 'portability' ? 'reject' : false);
      });
    }
    await check('access remains available after withdrawal', async () => {
      const r = await request('POST', '/v1/gdpr/access', {});
      assert.equal(r.status, 200); assert.equal(r.body.request.validated, true);
    });
    await check('name-only erasure can return an accepted delete plan', async () => {
      const r = await request('POST', '/v1/gdpr/erasure', { fields: ['name'], reason: 'withdrawn_consent' });
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'accept');
      assert.equal(r.body.actions.delete.target_user_id, user.id);
      assert.deepEqual(r.body.actions.delete.fields, ['name']);
    });
    await check('actual database record is unchanged by decision-only plans', async () => {
      const r = await request('POST', '/v1/auth/login', { email, password: 'Integration123' }, false);
      assert.equal(r.status, 200); assert.equal(r.body.user.name, 'GDPR Integration User');
    });
    await check('test administrator can assess a breach', async () => {
      // Trusted test setup changes role in the actual isolated DB, not through a public privilege escalation.
      const mongoose = require('mongoose');
      const connection = await mongoose.createConnection(message.mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
      try {
        await connection.collection('users').updateOne({ _id: mongoose.Types.ObjectId(user.id) }, { $set: { role: 'admin' } });
      } finally { await connection.close(); }
      const r = await request('POST', '/v1/gdpr/breach', { incident_id: 'integration-incident' });
      assert.equal(r.status, 200); assert.equal(r.body.decision, 'notify_users');
      assert.deepEqual(r.body.actions.notify_users.users, [user.id]);
    });
    await check('client cannot choose another user', async () => {
      assert.equal((await request('POST', '/v1/gdpr/access', { user_id: 'someone-else' })).status, 400);
    });
    await check('invalid consent update is rejected', async () => {
      assert.equal((await request('PATCH', '/v1/gdpr/consent', { value: 'yes', withdrawn: 'false' })).status, 400);
    });
    await check('unsupported policy has explicit error', async () => {
      assert.equal((await request('POST', '/v1/gdpr/unknown', {})).status, 400);
    });
    await check('OPA outage returns HTTP 502', async () => {
      const exited = once(opa, 'exit'); opa.kill(); await exited;
      assert.equal((await request('POST', '/v1/gdpr/consent', {})).status, 502);
    });
    await check('shared router and Rego policies unchanged', async () => assert.deepEqual(hashes(), before));
    require('./test-support.cjs').recordResult({
      repository: 'hagopj13/node-express-boilerplate',
      commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: path.join(__dirname, '..'), encoding: 'utf8', windowsHide: true }).trim(),
      timestamp: new Date().toISOString(), checks, passed: checks,
      scenarios: outcomes,
      policies: ['consent', 'lawful', 'information', 'access', 'rectification', 'erasure',
        'restriction', 'portability', 'objection', 'complaint', 'breach'],
      addedEndpoints: [
        ...['consent','lawful','information','access','rectification','erasure','restriction',
          'portability','objection','complaint','breach'].map(name => 'POST /v1/gdpr/' + name),
        'PATCH /v1/gdpr/consent',
      ],
      limitations: ['Access policy returns field metadata, not stored values',
        'Business policy metadata is synthetic; users and consents are MongoDB records',
        'Decision/action plans are returned without executing side effects'],
      sourceHashes: Object.fromEntries(files.map((file, i) => [path.relative(privacyRoot, file), before[i]])),
    });
    console.log('\nIntegration result: ' + checks + '/' + checks + ' passed');
  } finally {
    if (backend && backend.exitCode === null && backend.signalCode === null) {
      const exited = once(backend, 'exit'); backend.send('stop');
      const timer = setTimeout(() => backend.kill(), 15000); await exited; clearTimeout(timer);
    }
    if (opa.exitCode === null && opa.signalCode === null) opa.kill();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
