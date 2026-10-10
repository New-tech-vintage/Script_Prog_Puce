'use strict';

// Tests de lib/programmer.js : vecteurs NXP AN12196 (Rev. 2.0), plan de programmation,
// et simulation complète sur une puce factice (aucun lecteur).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const prog = require('../lib/programmer');
const sm = require('../lib/secure-messaging');
const sdm = require('../lib/sdm-config');

const join = (...parts) => parts.join('');

const S_T14 = {
  ti: '9D00C4DF', cmdCtr: 0,
  encKey: '1309C877509E5A215007FF0ED19CA564',
  macKey: '4C6626F5E72EA694202139295C7A7FC7',
};
const S_T25 = {
  ti: '7614281A', cmdCtr: 2,
  encKey: '4CF3CB41A22583A61E89B158D252FC53',
  macKey: '5529860B2FC5FB6154B7F28361D30BF9',
};

test('CRC32 NXP (AN12196 Table 25)', () => {
  assert.equal(prog.crc32Nxp('F3847D627727ED3BC9C4CC050489B966'), '789DFADC');
});

test('AN12196 Table 25 — ChangeKey cas 1 (clé 2, session clé 0)', () => {
  assert.equal(
    prog.buildChangeKeyOther(S_T25, '02', '00'.repeat(16), 'F3847D627727ED3BC9C4CC050489B966', '01'),
    '90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600');
});

test('AN12196 Table 26 — ChangeKey cas 2 (clé 0, session clé 0)', () => {
  assert.equal(
    prog.buildChangeKeySame({ ...S_T25, cmdCtr: 3 }, '00', '5004BF991F408672B1EF00F08F9E8647', '01'),
    '90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200');
});

test('AN12196 Table 18 — ChangeFileSettings', () => {
  const settings = sdm.buildFileSettings({
    metaRead: 0x2, fileRead: 0x1, ctrRet: 0x1,
    piccDataOffset: 0x20, sdmMacInputOffset: 0x43, sdmMacOffset: 0x43,
  });
  assert.equal(prog.buildChangeFileSettings({ ...S_T14, cmdCtr: 1 }, settings),
    '905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400');
});

test('AN12196 Table 17 — WriteData NDEF en CommMode.FULL', () => {
  const data = join(
    '0051D1014D550463686F6F73652E75726C2E63',
    '6F6D2F6E7461673432343F653D3030303030303',
    '030303030303030303030303030303030303030303030',
    '30303026633D30303030303030303030303030303030',
    '000000000000000000000000000000000000000000000',
    '000000000000000000000000000000000000000000000',
  );
  const apdu = prog.buildWriteData(S_T14, data, { mode: 'full' });
  assert.equal(apdu.slice(0, 24), '908D00009F02000000800000');
  assert.equal(apdu.slice(-18), 'D1D9A8499661EBF300');
});

test('WriteData NDEF en CommMode.Plain (données de la Table 16)', () => {
  // Header 02 | offset 000000 | longueur 0x53 → 530000 ; Lc = 7 + 0x53 = 0x5A ; ni chiffrement ni MAC.
  const data = join(
    '0051D1014D550463686F6F73652E75726C2E63',
    '6F6D2F6E7461673432343F653D3030303030303',
    '030303030303030303030303030303030303030303030',
    '30303026633D30303030303030303030303030303030',
  );
  assert.equal(prog.buildWriteData(S_T14, data), `908D00005A02000000530000${data}00`);
});

test('plan de programmation : ordre et garde-fous', async (t) => {
  const cfg = sdm.ntvSdmConfig();
  const K0 = '11'.repeat(16);
  const K1 = '22'.repeat(16);

  await t.test('ordre : NDEF (4 fragments) → FileSettings → K1 → K0 en dernier', () => {
    const plan = prog.programmingPlan({ k0: K0, k1: K1, sdm: cfg });
    assert.deepEqual(plan.map((s) => s.build({ ...S_T14 }).slice(2, 4)), ['8D', '8D', '8D', '8D', '5F', 'C4', 'C4']);
    assert.match(plan.at(-1).name, /clé 0/);
    assert.equal(plan.at(-1).responseMode, 'plain');
  });
  await t.test('fragments WriteData : offsets 0/32/64/96, aucune APDU plus grande que ChangeKey', () => {
    const plan = prog.programmingPlan({ k0: K0, k1: K1, sdm: cfg });
    const apdus = plan.map((s) => s.build({ ...S_T14 }));
    // Header WriteData : 02 | offset (3 o, LSB) | longueur (3 o, LSB)
    assert.deepEqual(apdus.slice(0, 4).map((a) => a.slice(10, 24)),
      ['02000000200000', '02200000200000', '02400000200000', '026000000C0000']);
    const longest = Math.max(...apdus.slice(0, 4).map((a) => a.length / 2));
    assert.equal(longest, 45);
    assert.ok(longest <= apdus.at(-1).length / 2);
  });
  await t.test('fragments recollés = fichier NDEF complet', () => {
    for (const size of [8, 16, 32, 48, 107, 108, 200]) {
      const chunks = prog.chunkFile(cfg.fileHex, size);
      assert.equal(chunks.map((c) => c.dataHex).join(''), cfg.fileHex);
      assert.ok(chunks.every((c) => c.dataHex.length / 2 <= size));
      assert.equal(chunks[0].offset, 0);
    }
    assert.throws(() => prog.chunkFile(cfg.fileHex, 0), /invalide/);
  });
  await t.test('chunkSize = 48 → 3 fragments (48, 48, 12)', () => {
    const plan = prog.programmingPlan({ k0: K0, k1: K1, sdm: cfg, chunkSize: 48 });
    assert.equal(plan.filter((s) => s.name.startsWith('WriteData')).length, 3);
  });
  await t.test('refuse une clé nulle, deux clés identiques, une clé mal formée', () => {
    assert.throws(() => prog.programmingPlan({ k0: '00'.repeat(16), k1: K1, sdm: cfg }), /nulles/);
    assert.throws(() => prog.programmingPlan({ k0: K0, k1: K0, sdm: cfg }), /différentes/);
    assert.throws(() => prog.programmingPlan({ k0: 'ABC', k1: K1, sdm: cfg }), /16 octets/);
    assert.throws(() => prog.programmingPlan({ k0: K0, k1: K1 }), /SDM manquante/);
  });
});

// --- Simulation : puce NTAG 424 factice ------------------------------------------
// Elle déchiffre et vérifie chaque commande comme le ferait la vraie puce, applique ses
// effets, puis génère l'URL SUN d'un scan. Le scan est enfin vérifié côté « backend ».

function fakeChip({ uid, session }) {
  const state = {
    keys: { '00': '00'.repeat(16), '01': '00'.repeat(16) },
    file: Buffer.alloc(256),
    settings: null,
    sessionOpen: true,
    sdmReadCtr: 0,
  };
  const decrypt = (s, enc) => {
    const d = crypto.createDecipheriv('aes-128-cbc', Buffer.from(s.encKey, 'hex'),
      Buffer.from(sm.ivCommand(s.encKey, s.ti, s.cmdCtr), 'hex'));
    d.setAutoPadding(false);
    return sm.unpad(Buffer.concat([d.update(Buffer.from(enc, 'hex')), d.final()]).toString('hex').toUpperCase());
  };
  const HEADER_LEN = { '8D': 7, '5F': 1, C4: 1 };

  function transmit(apdu) {
    if (!state.sessionOpen) return '91AE';
    const cmd = apdu.slice(2, 4);
    const body = apdu.slice(10, -2);
    const header = body.slice(0, HEADER_LEN[cmd] * 2);
    const s = session;
    let respMode = 'full';
    let reply = '9100';

    if (cmd === '8D') {
      // Fichier NDEF en CommMode.Plain : ni MAC ni chiffrement.
      const data = Buffer.from(body.slice(14), 'hex');
      const off = Buffer.from(header.slice(2, 8), 'hex').readUIntLE(0, 3);
      const len = Buffer.from(header.slice(8, 14), 'hex').readUIntLE(0, 3);
      assert.equal(len, data.length);
      data.copy(state.file, off);
      respMode = 'plain';
    } else {
      const enc = body.slice(header.length, -16);
      const mac = body.slice(-16);
      if (mac !== sm.macCommand(s.macKey, cmd, s.cmdCtr, s.ti, header, enc)) return '911E';
      const data = decrypt(s, enc);
      if (cmd === '5F') {
        state.settings = data;
      } else if (header === '00') {
        state.keys['00'] = data.slice(0, 32);
        state.sessionOpen = false; // changement de la clé de session → session terminée
        respMode = 'none';
      } else {
        const newKey = Buffer.from(data.slice(0, 32), 'hex')
          .map((b, i) => b ^ Buffer.from(state.keys[header], 'hex')[i]).toString('hex').toUpperCase();
        if (data.slice(34, 42) !== prog.crc32Nxp(newKey)) return '911E';
        state.keys[header] = newKey;
      }
    }
    if (respMode === 'full') {
      reply = sm.macResponse(s.macKey, '00', s.cmdCtr, s.ti, '') + '9100';
    }
    if (respMode !== 'none') s.cmdCtr += 1;
    return reply;
  }

  // Lecture NDEF par un téléphone : la puce remplace les zéros par UID, compteur et CMAC.
  function scan() {
    const st = state.settings;
    // Octets : FileOption(0) AR(1-2) SDMOptions(3) SDMAR(4-5) UID(6) Ctr(9) MACInput(12) MAC(15)
    const off = (byte) => Buffer.from(st.slice(byte * 2, byte * 2 + 6), 'hex').readUIntLE(0, 3);
    const uidOff = off(6);
    const ctrOff = off(9);
    const macOff = off(15);
    state.sdmReadCtr += 1;
    const ctrHex = state.sdmReadCtr.toString(16).toUpperCase().padStart(6, '0');
    const f = Buffer.from(state.file);
    f.write(uid, uidOff, 'ascii');
    f.write(ctrHex, ctrOff, 'ascii');
    f.write(sdm.sdmMac(state.keys['01'], uid, ctrHex), macOff, 'ascii');
    const nlen = f.readUInt16BE(0);
    return 'https://' + f.subarray(7, 2 + nlen).toString('ascii');
  }

  return { transmit, scan, state };
}

test('simulation : programmation complète sur puce factice puis scan vérifié', () => {
  const uid = '0459888A2B1D90';
  const K0 = crypto.randomBytes(16).toString('hex').toUpperCase();
  const K1 = crypto.randomBytes(16).toString('hex').toUpperCase();
  const cfg = sdm.ntvSdmConfig();

  // Session côté programmateur et côté puce (mêmes clés, comme après AuthenticateEV2First).
  const keys = { ti: 'A1B2C3D4', encKey: crypto.randomBytes(16).toString('hex').toUpperCase(),
    macKey: crypto.randomBytes(16).toString('hex').toUpperCase() };
  const host = { ...keys, cmdCtr: 0 };
  const chip = fakeChip({ uid, session: { ...keys, cmdCtr: 0 } });

  for (const step of prog.programmingPlan({ k0: K0, k1: K1, sdm: cfg })) {
    const resp = chip.transmit(step.build(host));
    const r = sm.parseResponse(host, resp, step.responseMode);
    assert.equal(r.ok, true, `${step.name} : ${r.sw}`);
    host.cmdCtr = r.cmdCtr;
  }

  assert.equal(chip.state.keys['00'], K0);
  assert.equal(chip.state.keys['01'], K1);
  assert.equal(chip.state.settings, cfg.fileSettingsHex);
  assert.equal(chip.transmit('905F00000102' + '00'), '91AE', 'plus aucune commande sans ré-authentification');

  // Deux scans : URL au format du contrat backend, CMAC vérifiable avec K1, compteur qui avance.
  for (const expectedCtr of ['000001', '000002']) {
    const url = new URL(chip.scan());
    assert.equal(url.origin + url.pathname, 'https://backend-contracts-ntv.onrender.com/api/nfc/verify');
    assert.equal(url.searchParams.get('uid'), uid);
    assert.equal(url.searchParams.get('ctr'), expectedCtr);
    assert.match(url.searchParams.get('cmac'), /^[0-9A-F]{16}$/);
    assert.equal(sdm.sdmMac(K1, uid, url.searchParams.get('ctr')), url.searchParams.get('cmac'));
    assert.notEqual(sdm.sdmMac(K0, uid, url.searchParams.get('ctr')), url.searchParams.get('cmac'));
  }
});
