'use strict';

// Tests de lib/secure-messaging.js contre les vecteurs officiels NXP AN12196 (Rev. 2.0).
// Les hexas longs sont recopiés tels qu'imprimés dans le PDF (lignes coupées) puis recollés.

const test = require('node:test');
const assert = require('node:assert/strict');
const sm = require('../lib/secure-messaging');

const join = (...parts) => parts.join('');

// Table 17 (§5.8.2) — WriteData NDEF, CommMode.FULL, session de la Table 14.
const T17 = {
  session: {
    ti: '9D00C4DF', cmdCtr: 0,
    encKey: '1309C877509E5A215007FF0ED19CA564',
    macKey: '4C6626F5E72EA694202139295C7A7FC7',
  },
  // CmdData de l'étape 7 : 128 octets de NDEF (le bloc 80 00… final imprimé dans la doc est le padding).
  data: join(
    '0051D1014D550463686F6F73652E75726C2E63',
    '6F6D2F6E7461673432343F653D3030303030303',
    '030303030303030303030303030303030303030303030',
    '30303026633D30303030303030303030303030303030',
    '000000000000000000000000000000000000000000000',
    '000000000000000000000000000000000000000000000',
  ),
  ivc: 'D2CB7277A17841A06654A48188C1F8F5',
  enc: join(
    '421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58',
    'D347F343CFFC768BFE596C706BC00F2176781D4B0242642',
    'A0FF5A42C461AAF894D9A1284B8C76BCFA658ACD40555',
    'D362E08DB15CF421B51283F9064BCBE20E96CAE545B40',
    '7C9D651A3315B27373772E5DA2367D2064AE054AF996C6',
    'F1F669170FA88CE8C4E3A4A7BBBEF0FD971FF532C3A802',
    'AF745660F2B4',
  ),
  macT: 'D1D9A8499661EBF3',
  apdu: join(
    '908D00009F02000000800000421C73A27D827658AF481',
    'FDFF20A5025B559D0E3AA21E58D347F343CFFC768BFE596',
    'C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9',
    'A1284B8C76BCFA658ACD40555D362E08DB15CF421B51283',
    'F9064BCBE20E96CAE545B407C9D651A3315B27373772E5',
    'DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3A4A7',
    'BBBEF0FD971FF532C3A802AF745660F2B4D1D9A8499661',
    'EBF300',
  ),
  rapdu: 'FC222E5F7A5424529100',
};

test('CmdCtr : encodage 2 octets poids faible en premier', () => {
  assert.equal(sm.cmdCtrToHex(0), '0000');
  assert.equal(sm.cmdCtrToHex(1), '0100');
  assert.equal(sm.cmdCtrToHex(3), '0300');
  assert.equal(sm.cmdCtrToHex(0x1234), '3412');
  assert.equal(sm.nextCmdCtr(0), 1);
  assert.throws(() => sm.nextCmdCtr(0xffff), /saturé/);
  assert.throws(() => sm.cmdCtrToHex(-1), /invalide/);
});

test('padding ISO 9797-1 M2', () => {
  assert.equal(sm.pad('02'), '02800000000000000000000000000000');
  assert.equal(sm.pad('00'.repeat(16)), '00'.repeat(16) + '80' + '00'.repeat(15));
  assert.equal(sm.unpad('04958CAA5C5E80800000000000000000'), '04958CAA5C5E80');
  assert.throws(() => sm.unpad('00'.repeat(16)), /Padding invalide/);
});

test('MAC tronqué : octets d\'indice impair (AN12196 Table 7)', () => {
  assert.equal(sm.truncateMac('B565AC978FA46D5784C845CD1444102C'), '6597A457C8CD442C');
});

test('AN12196 Table 7 — GetFileSettings, CommMode.MAC', async (t) => {
  const s = { ti: '7A21085E', cmdCtr: 0, macKey: '8248134A386E86EB7FAF54A52E536CB6', encKey: '00'.repeat(16) };
  const respData = '0040EEEE000100D1FE001F00004400004400002000006A0000';
  await t.test('MAC de commande', () => {
    assert.equal(sm.macCommand(s.macKey, 'F5', 0, s.ti, '02'), '6597A457C8CD442C');
  });
  await t.test('C-APDU', () => {
    assert.equal(sm.buildCommand(s, 'F5', '02', '', 'mac'), '90F5000009026597A457C8CD442C00');
  });
  await t.test('MAC de réponse', () => {
    assert.equal(sm.macResponse(s.macKey, '00', 0, s.ti, respData), '2A474282E7A47986');
  });
  await t.test('parse R-APDU', () => {
    assert.deepEqual(sm.parseResponse(s, respData + '2A474282E7A479869100', 'mac'),
      { ok: true, sw: '9100', data: respData, cmdCtr: 1 });
  });
});

test('AN12196 Table 17 — WriteData NDEF, CommMode.FULL', async (t) => {
  const s = T17.session;
  await t.test('IVc', () => {
    assert.equal(sm.ivCommand(s.encKey, s.ti, 0), T17.ivc);
  });
  await t.test('chiffrement des données', () => {
    assert.equal(sm.encryptCommandData(s.encKey, s.ti, 0, T17.data), T17.enc);
  });
  await t.test('MAC de commande', () => {
    assert.equal(sm.macCommand(s.macKey, '8D', 0, s.ti, '02000000800000', T17.enc), T17.macT);
  });
  await t.test('C-APDU complète', () => {
    assert.equal(sm.buildCommand(s, '8D', '02000000800000', T17.data), T17.apdu);
  });
  await t.test('parse R-APDU (MAC vérifié, CmdCtr → 1)', () => {
    assert.deepEqual(sm.parseResponse(s, T17.rapdu), { ok: true, sw: '9100', data: '', cmdCtr: 1 });
  });
});

test('AN12196 Table 18 — ChangeFileSettings, CmdCtr = 1', async (t) => {
  const s = { ...T17.session, cmdCtr: 1 };
  const data = '4000E0C1F121200000430000430000';
  await t.test('IVc', () => {
    assert.equal(sm.ivCommand(s.encKey, s.ti, 1), '3E27082AB2ACC1EF55C57547934E9962');
  });
  await t.test('chiffrement des données', () => {
    assert.equal(sm.encryptCommandData(s.encKey, s.ti, 1, data), '61B6D97903566E84C3AE5274467E89EA');
  });
  await t.test('MAC de commande', () => {
    assert.equal(sm.macCommand(s.macKey, '5F', 1, s.ti, '02', '61B6D97903566E84C3AE5274467E89EA'), 'D799B7C1A0EF7A04');
  });
  await t.test('C-APDU complète', () => {
    assert.equal(sm.buildCommand(s, '5F', '02', data),
      '905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400');
  });
  await t.test('parse R-APDU (CmdCtr → 2)', () => {
    assert.deepEqual(sm.parseResponse(s, '57BFF87B1241E93D9100'), { ok: true, sw: '9100', data: '', cmdCtr: 2 });
  });
});

test('AN12196 Table 21 — WriteData fichier propriétaire, session de la Table 19', async (t) => {
  const s = {
    ti: '7614281A', cmdCtr: 0,
    encKey: '7A93D6571E4B180FCA6AC90C9A7488D4',
    macKey: 'FC4AF159B62E549B5812394CAB1918CC',
  };
  await t.test('IVc', () => {
    assert.equal(sm.ivCommand(s.encKey, s.ti, 0), '4C651A64261A90307B6C293F611C7F7B');
  });
  await t.test('chiffrement des données', () => {
    assert.equal(sm.encryptCommandData(s.encKey, s.ti, 0, '0102030405060708090A'), '6B5E6804909962FC4E3FF5522CF0F843');
  });
  await t.test('C-APDU complète', () => {
    assert.equal(sm.buildCommand(s, '8D', '030000000A0000', '0102030405060708090A'),
      '908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00');
  });
  await t.test('parse R-APDU', () => {
    assert.deepEqual(sm.parseResponse(s, 'C26D236E4A7C046D9100'), { ok: true, sw: '9100', data: '', cmdCtr: 1 });
  });
});

test('AN12196 Table 25 — ChangeKey cas 1 (clé 2 ≠ clé authentifiée), CmdCtr = 2', async (t) => {
  const s = {
    ti: '7614281A', cmdCtr: 2,
    encKey: '4CF3CB41A22583A61E89B158D252FC53',
    macKey: '5529860B2FC5FB6154B7F28361D30BF9',
  };
  const keyData = 'F3847D627727ED3BC9C4CC050489B96601789DFADC';
  const enc = '2CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC7';
  await t.test('IVc', () => {
    assert.equal(sm.ivCommand(s.encKey, s.ti, 2), '307EDE1814707F30CFE603DD6CA62353');
  });
  await t.test('chiffrement des données', () => {
    assert.equal(sm.encryptCommandData(s.encKey, s.ti, 2, keyData), enc);
  });
  await t.test('C-APDU complète', () => {
    assert.equal(sm.buildCommand(s, 'C4', '02', keyData), `90C400002902${enc}5D0CE20BCD1D06E600`);
  });
  await t.test('parse R-APDU', () => {
    assert.deepEqual(sm.parseResponse(s, '203BB55D1089D5879100'), { ok: true, sw: '9100', data: '', cmdCtr: 3 });
  });
});

test('AN12196 Table 26 — ChangeKey cas 2 (clé 0 = clé authentifiée), CmdCtr = 3', async (t) => {
  const s = {
    ti: '7614281A', cmdCtr: 3,
    encKey: '4CF3CB41A22583A61E89B158D252FC53',
    macKey: '5529860B2FC5FB6154B7F28361D30BF9',
  };
  const enc = 'C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FD';
  await t.test('IVc', () => {
    assert.equal(sm.ivCommand(s.encKey, s.ti, 3), '01602D579423B2797BE8B478B0B4D27B');
  });
  await t.test('C-APDU complète', () => {
    assert.equal(sm.buildCommand(s, 'C4', '00', '5004BF991F408672B1EF00F08F9E864701'),
      `90C400002900${enc}A6610234BDED643200`);
  });
  // La puce répond 9100 sans MAC (la session est terminée par le changement de clé) :
  // le mode 'plain' permet de lire ce statut.
  await t.test('parse R-APDU sans MAC', () => {
    assert.equal(sm.parseResponse(s, '9100', 'plain').ok, true);
  });
});

test('AN12196 Table 27 — SetConfiguration (Random ID), CommMode.FULL', async (t) => {
  const s = {
    ti: 'D779B1D0', cmdCtr: 0,
    encKey: '7951A705F47F3C29B596454DC1490383',
    macKey: 'FE4EDBF46536557E304682F33E63A84F',
  };
  await t.test('IVc', () => {
    assert.equal(sm.ivCommand(s.encKey, s.ti, 0), 'FEFB918047F385563FA8356DE86E5182');
  });
  await t.test('C-APDU complète (calcul seul, rien n\'est envoyé)', () => {
    assert.equal(sm.buildCommand(s, '5C', '00', '02'),
      '905C000019008EA0138A7AF6FC8E99DF2A3A305602C43A7A3C9228C3134A00');
  });
  await t.test('parse R-APDU', () => {
    assert.deepEqual(sm.parseResponse(s, '86044208CAD1676A9100'), { ok: true, sw: '9100', data: '', cmdCtr: 1 });
  });
});

test('AN12196 Table 28 — GetCardUID, réponse chiffrée', async (t) => {
  const s = {
    ti: 'DF055522', cmdCtr: 0,
    encKey: '2B4D963C014DC36F24F69A50A394F875',
    macKey: '379D32130CE61705DD5FD8C36B95D764',
  };
  await t.test('C-APDU (ni header ni données : MAC seul)', () => {
    assert.equal(sm.buildCommand(s, '51'), '90510000088E2C155ADDA99BE300');
  });
  await t.test('IVr (utilise CmdCtr + 1)', () => {
    assert.equal(sm.ivResponse(s.encKey, s.ti, 0), '7F6BB0B278EA054CBD238C5D9E9E342B');
  });
  await t.test('déchiffrement de la réponse', () => {
    assert.equal(sm.decryptResponseData(s.encKey, s.ti, 0, '70756055688505B52A5E26E59E329CD6'), '04958CAA5C5E80');
  });
  await t.test('parse R-APDU complète → UID', () => {
    assert.deepEqual(sm.parseResponse(s, '70756055688505B52A5E26E59E329CD6595F672298EA41B79100'),
      { ok: true, sw: '9100', data: '04958CAA5C5E80', cmdCtr: 1 });
  });
});

test('sécurité : réponse altérée ou erreur de la puce', async (t) => {
  const s = T17.session;
  await t.test('MAC faux → exception', () => {
    assert.throws(() => sm.parseResponse(s, 'FC222E5F7A5424539100'), /MAC de réponse invalide/);
  });
  await t.test('mauvais CmdCtr → exception (session désynchronisée)', () => {
    assert.throws(() => sm.parseResponse({ ...s, cmdCtr: 1 }, T17.rapdu), /MAC de réponse invalide/);
  });
  await t.test('statut d\'erreur 91AE → ok = false, CmdCtr inchangé', () => {
    assert.deepEqual(sm.parseResponse(s, '91AE'), { ok: false, sw: '91AE', data: '', cmdCtr: 0 });
  });
});
