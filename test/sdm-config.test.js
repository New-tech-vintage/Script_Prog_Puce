'use strict';

// Tests de lib/sdm-config.js : vecteurs NXP AN12196 (Rev. 2.0) + calcul manuel pour l'URL NTV.

const test = require('node:test');
const assert = require('node:assert/strict');
const sdm = require('../lib/sdm-config');

const join = (...parts) => parts.join('');

test('offsets sur 3 octets, poids faible en premier', () => {
  assert.equal(sdm.offsetToHex(0x20), '200000');
  assert.equal(sdm.offsetToHex(0x43), '430000');
  assert.equal(sdm.offsetToHex(0x123456), '563412');
  assert.throws(() => sdm.offsetToHex(-1), /invalide/);
});

test('AN12196 Tables 15-16 — fichier NDEF et offsets', async (t) => {
  const url = 'https://choose.url.com/ntag424?e=' + '0'.repeat(32) + '&c=' + '0'.repeat(16);
  const expected = join(
    '0051D1014D550463686F6F73652E75726C2E63',
    '6F6D2F6E7461673432343F653D3030303030303',
    '030303030303030303030303030303030303030303030',
    '30303026633D30303030303030303030303030303030',
  );
  const { fileHex, textStart } = sdm.uriNdefFile(url);
  const inFile = (marker) => textStart + url.indexOf(marker) + marker.length - 'https://'.length;

  await t.test('contenu du fichier (NLEN 0051, en-tête D1014D5504)', () => {
    assert.equal(fileHex, expected);
    assert.equal(fileHex.length / 2, 0x53);
  });
  await t.test('offset du miroir après "?e=" = 0x20 (32)', () => {
    assert.equal(inFile('?e='), 0x20);
  });
  await t.test('offset du CMAC après "&c=" = 0x43 (67)', () => {
    assert.equal(inFile('&c='), 0x43);
  });
});

test('AN12196 Table 18 — données de ChangeFileSettings', () => {
  // Exemple NXP : PICCData chiffrée (SDMMetaRead = clé 2), CMAC avec la clé 1.
  const hex = sdm.buildFileSettings({
    metaRead: 0x2, fileRead: 0x1, ctrRet: 0x1,
    piccDataOffset: 0x20, sdmMacInputOffset: 0x43, sdmMacOffset: 0x43,
  });
  assert.equal(hex, '4000E0C1F121200000430000430000');
});

test('URL NTV — fichier NDEF et offsets (calcul manuel)', async (t) => {
  // "https://" est abrégé par le code 04. Reste de l'URL :
  //   "backend-contracts-ntv.onrender.com"  34 car.
  //   "/api/nfc/verify"                     15 car.  → 49
  //   "?uid="                                5 car.  → 54
  // Le texte commence à l'octet 7 du fichier (NLEN 2 + D1 01 PL 55 04 = 5).
  //   uid  : 7 + 54           = 61 (0x3D)
  //   ctr  : 61 + 14 + 5 "&ctr="  = 80 (0x50)
  //   cmac : 80 + 6 + 6 "&cmac=" = 92 (0x5C)
  //   fin  : 92 + 16          = 108 octets ; NLEN = 106 (0x6A) ; PL = 102 (0x66)
  const cfg = sdm.ntvSdmConfig();
  const file = Buffer.from(cfg.fileHex, 'hex');

  await t.test('URL avec zéros aux emplacements miroir', () => {
    assert.equal(cfg.url,
      'https://backend-contracts-ntv.onrender.com/api/nfc/verify?uid=00000000000000&ctr=000000&cmac=0000000000000000');
  });
  await t.test('offsets', () => {
    assert.deepEqual(cfg.offsets, { uidOffset: 0x3d, sdmReadCtrOffset: 0x50, sdmMacInputOffset: 0x5c, sdmMacOffset: 0x5c });
  });
  await t.test('en-tête NDEF : NLEN 006A, D1 01 66 55 04', () => {
    assert.equal(cfg.length, 108);
    assert.equal(cfg.fileHex.slice(0, 14), '006AD101665504');
  });
  await t.test('chaque offset pointe sur les zéros, juste après le "="', () => {
    const at = (off, len) => file.subarray(off, off + len).toString('ascii');
    assert.equal(at(cfg.offsets.uidOffset - 5, 5), '?uid=');
    assert.equal(at(cfg.offsets.uidOffset, 14), '0'.repeat(14));
    assert.equal(at(cfg.offsets.sdmReadCtrOffset - 5, 5), '&ctr=');
    assert.equal(at(cfg.offsets.sdmReadCtrOffset, 6), '0'.repeat(6));
    assert.equal(at(cfg.offsets.sdmMacOffset - 6, 6), '&cmac=');
    assert.equal(at(cfg.offsets.sdmMacOffset, 16), '0'.repeat(16));
    assert.equal(cfg.offsets.sdmMacOffset + 16, file.length);
  });
  await t.test('données de ChangeFileSettings', () => {
    // 40 | 00E0 | C1 | FEE1 | UIDOffset 3D0000 | SDMReadCtrOffset 500000 | MACInput 5C0000 | MAC 5C0000
    assert.equal(cfg.fileSettingsHex, '4000E0C1FEE13D00005000005C00005C0000');
  });
});

test('modèle d\'URL invalide → erreur', () => {
  assert.throws(() => sdm.buildSdmNdef('https://x.com/?uid={uid}&cmac={cmac}'), /manquant : \{ctr\}/);
  assert.throws(() => sdm.buildSdmNdef('https://x.com/?uid={uid}&ctr={ctr}&cmac={cmac}&x=1'), /toute fin/);
  assert.throws(() => sdm.buildSdmNdef('https://x.com/?u={uid}&v={uid}&ctr={ctr}&cmac={cmac}'), /double/);
  assert.throws(() => sdm.buildSdmNdef('http://x.com/?uid={uid}&ctr={ctr}&cmac={cmac}'), /https/);
});

test('AN12196 Table 1 — KSesSDMFileReadMAC (SV2)', () => {
  // SDMReadCtr = 010000 (poids faible d'abord) ⇔ "000001" dans l'URL.
  assert.equal(sdm.sdmSessionMacKey('5ACE7E50AB65D5D51FD5BF5A16B8205B', '04C767F2066180', '000001'),
    '3A3E8110E05311F7A3FCF0D969BF2B48');
});

test('AN12196 Table 4 — SDMMAC sur entrée vide', async (t) => {
  // SDMReadCtr = 3D0000 (poids faible d'abord) ⇔ "00003D" dans l'URL.
  await t.test('clé de session', () => {
    assert.equal(sdm.sdmSessionMacKey('00'.repeat(16), '04DE5F1EACC040', '00003D'),
      '3FB5F6E3A807A03D5E3570ACE393776F');
  });
  await t.test('SDMMAC', () => {
    assert.equal(sdm.sdmMac('00'.repeat(16), '04DE5F1EACC040', '00003D'), '94EED9EE65337086');
  });
});
