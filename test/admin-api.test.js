'use strict';

// Tests de lib/admin-api.js : configuration, corps de link-chip, masquage, appel HTTP (fetch simulé).

const test = require('node:test');
const assert = require('node:assert/strict');
const api = require('../lib/admin-api');

const UID = '0456898A2B1D90';
const K1 = 'FA4EF4EF4EF4EF4EF4EF4EF4EF4EF4EF'; // fausse clé de test

test('configuration : variables obligatoires et HTTPS imposé', () => {
  const env = { SUPABASE_URL: 'https://x.supabase.co', SUPABASE_ANON_KEY: 'anon', BACKEND_URL: 'https://api.example/' };
  assert.equal(api.loadAdminConfig(env).backendUrl, 'https://api.example');
  assert.throws(() => api.loadAdminConfig({ ...env, BACKEND_URL: 'http://api.example' }), /https/);
  assert.throws(() => api.loadAdminConfig({ ...env, SUPABASE_ANON_KEY: '' }), /SUPABASE_ANON_KEY/);
});

test('recherche : les jokers LIKE tapés par l\'utilisateur sont échappés', () => {
  assert.equal(api.escapeLike('veste 100%_coton\\'), 'veste 100\\%\\_coton\\\\');
  assert.equal(api.escapeLike('Veste'), 'Veste');
});

test('corps link-chip', async (t) => {
  await t.test('avec couleur', () => {
    assert.deepEqual(api.linkChipBody({ uid: UID, sunSecret: K1, itemId: 50, size: 'S', color: 'Noir' }),
      { uid: UID, sun_secret: K1, item_id: 50, size: 'S', color: 'Noir' });
  });
  await t.test('sans couleur : champ omis', () => {
    assert.deepEqual(api.linkChipBody({ uid: UID, sunSecret: K1, itemId: 50, size: 'S', color: null }),
      { uid: UID, sun_secret: K1, item_id: 50, size: 'S' });
  });
  await t.test('entrées invalides refusées', () => {
    assert.throws(() => api.linkChipBody({ uid: 'XYZ', sunSecret: K1, itemId: 50, size: 'S' }), /UID/);
    assert.throws(() => api.linkChipBody({ uid: UID, sunSecret: 'abc', itemId: 50, size: 'S' }), /sun_secret/);
    assert.throws(() => api.linkChipBody({ uid: UID, sunSecret: K1, itemId: 0, size: 'S' }), /item_id/);
    assert.throws(() => api.linkChipBody({ uid: UID, sunSecret: K1, itemId: 50, size: '' }), /taille/);
  });
});

test('appel link-chip (fetch simulé)', async (t) => {
  const calls = [];
  const fakeFetch = (status, payload) => async (url, opts) => {
    calls.push({ url, opts });
    return { ok: status < 300, status, text: async () => (typeof payload === 'string' ? payload : JSON.stringify(payload)) };
  };

  await t.test('succès : URL, en-têtes, corps, réponse', async () => {
    const r = await api.linkChip({
      backendUrl: 'https://api.example', token: 'JWT', fetchImpl: fakeFetch(200, { exemplaire: { serial_number: 7, size: 'S', color: 'Noir' } }),
      uid: UID, sunSecret: K1, itemId: 50, size: 'S', color: 'Noir',
    });
    const c = calls.at(-1);
    assert.equal(c.url, 'https://api.example/api/admin/link-chip');
    assert.equal(c.opts.method, 'POST');
    assert.equal(c.opts.headers.Authorization, 'Bearer JWT');
    assert.deepEqual(JSON.parse(c.opts.body), { uid: UID, sun_secret: K1, item_id: 50, size: 'S', color: 'Noir' });
    assert.ok(c.opts.signal, 'délai maximal posé');
    assert.equal(r.ok, true);
    assert.deepEqual(api.exemplaireFrom(r.body), { serialNumber: 7, size: 'S', color: 'Noir' });
  });
  await t.test('erreur HTTP : renvoyée, pas levée', async () => {
    const r = await api.linkChip({
      backendUrl: 'https://api.example', token: 'JWT', fetchImpl: fakeFetch(409, { error: 'aucun exemplaire libre' }),
      uid: UID, sunSecret: K1, itemId: 50, size: 'S',
    });
    assert.deepEqual(r, { ok: false, status: 409, body: { error: 'aucun exemplaire libre' } });
  });
  await t.test('réponse non JSON conservée en texte', async () => {
    const r = await api.linkChip({
      backendUrl: 'https://api.example', token: 'JWT', fetchImpl: fakeFetch(502, '<html>Bad Gateway</html>'),
      uid: UID, sunSecret: K1, itemId: 50, size: 'S',
    });
    assert.equal(r.body, '<html>Bad Gateway</html>');
  });
  await t.test('erreur réseau : levée', async () => {
    await assert.rejects(api.linkChip({
      backendUrl: 'https://api.example', token: 'JWT', fetchImpl: async () => { throw new Error('ECONNRESET'); },
      uid: UID, sunSecret: K1, itemId: 50, size: 'S',
    }), /ECONNRESET/);
  });
});

test('exemplaire : réponse directe ou sous "exemplaire"', () => {
  assert.deepEqual(api.exemplaireFrom({ serial_number: 3, size: 'M', color: null }), { serialNumber: 3, size: 'M', color: null });
  assert.deepEqual(api.exemplaireFrom('oops'), { serialNumber: null, size: null, color: null });
});

test('masquage : aucun secret ne survit à redact()', () => {
  const shown = api.redact({
    exemplaire: { serial_number: 7, sun_secret: K1 },
    access_token: 'eyJ.abc', note: `clé ${K1} dans un texte`,
  });
  assert.equal(JSON.stringify(shown).includes(K1), false);
  assert.equal(JSON.stringify(shown).includes('eyJ.abc'), false);
  assert.equal(shown.exemplaire.serial_number, 7);
  assert.equal(api.redact(`erreur ${K1}`), 'erreur «masqué»');
});
