'use strict';

// Assemblage des commandes de programmation SUN/SDM en Secure Messaging (NTAG 424 DNA).
// D'après NXP AN12196 §5.8, §5.9, §5.16. Fonctions pures : aucun accès NFC.

const zlib = require('zlib');
const sm = require('./secure-messaging');
const { NDEF_FILE_NO, offsetToHex } = require('./sdm-config');

const ZERO_KEY = '00'.repeat(16);

function checkKey(hex, name) {
  if (typeof hex !== 'string' || !/^[0-9A-Fa-f]{32}$/.test(hex)) throw new Error(`${name} : 16 octets hex attendus`);
  return hex.toUpperCase();
}

function checkKeyNo(keyNo) {
  if (!/^0[0-4]$/.test(keyNo)) throw new Error(`Numéro de clé invalide : ${keyNo}`);
  return keyNo;
}

function checkKeyVersion(v) {
  if (!/^[0-9A-Fa-f]{2}$/.test(v)) throw new Error(`Version de clé invalide : ${v}`);
  return v.toUpperCase();
}

function xorHex(a, b) {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return Buffer.from(x.map((v, i) => v ^ y[i])).toString('hex').toUpperCase();
}

// CRC32 NXP : CRC-32 IEEE sans inversion finale (JAMCRC), écrit poids faible en premier.
function crc32Nxp(hex) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(~zlib.crc32(Buffer.from(hex, 'hex')) >>> 0);
  return b.toString('hex').toUpperCase();
}

// Cmd.WriteData (8D) : header = FileNo || Offset(3) || Length(3), poids faible en premier.
// mode 'plain' tant que le fichier NDEF est en CommMode.Plain (cas usine et cible).
function buildWriteData(session, fileHex, { fileNo = NDEF_FILE_NO, offset = 0, mode = 'plain' } = {}) {
  const len = fileHex.length / 2;
  const header = fileNo + offsetToHex(offset) + offsetToHex(len);
  return sm.buildCommand(session, '8D', header, fileHex, mode);
}

// Découpe le fichier en morceaux de `chunkSize` octets au plus : [{ offset, dataHex }, ...].
// Contourne la limite de taille d'APDU de certains lecteurs (ACR122U).
function chunkFile(fileHex, chunkSize) {
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > 240) {
    throw new Error(`Taille de fragment invalide : ${chunkSize}`);
  }
  const chunks = [];
  for (let off = 0; off < fileHex.length / 2; off += chunkSize) {
    chunks.push({ offset: off, dataHex: fileHex.slice(off * 2, (off + chunkSize) * 2) });
  }
  return chunks;
}

// Cmd.ChangeFileSettings (5F) : toujours en CommMode.Full.
function buildChangeFileSettings(session, settingsHex, fileNo = NDEF_FILE_NO) {
  return sm.buildCommand(session, '5F', fileNo, settingsHex, 'full');
}

// Cmd.ChangeKey (C4), cas 1 : la clé changée n'est PAS celle de la session.
// Données = (AncienneClé ⊕ NouvelleClé) || Version || CRC32(NouvelleClé)
function buildChangeKeyOther(session, keyNo, oldKey, newKey, keyVersion = '01') {
  checkKeyNo(keyNo);
  const oldK = checkKey(oldKey, 'Ancienne clé');
  const newK = checkKey(newKey, 'Nouvelle clé');
  const data = xorHex(oldK, newK) + checkKeyVersion(keyVersion) + crc32Nxp(newK);
  return sm.buildCommand(session, 'C4', keyNo, data, 'full');
}

// Cmd.ChangeKey (C4), cas 2 : la clé changée EST celle de la session (la session se termine).
// Données = NouvelleClé || Version
function buildChangeKeySame(session, keyNo, newKey, keyVersion = '01') {
  checkKeyNo(keyNo);
  const data = checkKey(newKey, 'Nouvelle clé') + checkKeyVersion(keyVersion);
  return sm.buildCommand(session, 'C4', keyNo, data, 'full');
}

// Plan de programmation, dans l'ordre d'envoi. Chaque étape construit son APDU à partir de
// l'état COURANT de la session (le CmdCtr avance après chaque réponse réussie).
// La session doit avoir été ouverte avec la clé 0 actuelle (usine : zéros).
// L'URL NDEF est écrite en plusieurs WriteData de `chunkSize` octets au plus. Par défaut 32 :
// APDU de 45 octets, plus petite que ChangeKey / ChangeFileSettings (47 octets).
function programmingPlan({ k0, k1, sdm, oldK1 = ZERO_KEY, keyVersion = '01', chunkSize = 32 }) {
  const newK0 = checkKey(k0, 'K0');
  const newK1 = checkKey(k1, 'K1');
  if (newK0 === ZERO_KEY || newK1 === ZERO_KEY) throw new Error('K0 et K1 ne doivent pas être nulles');
  if (newK0 === newK1) throw new Error('K0 et K1 doivent être différentes');
  if (!sdm || !sdm.fileHex || !sdm.fileSettingsHex) throw new Error('Configuration SDM manquante');

  const chunks = chunkFile(sdm.fileHex, chunkSize);
  const writes = chunks.map(({ offset, dataHex }, i) => ({
    name: `WriteData ${i + 1}/${chunks.length} — URL NDEF, octets ${offset}-${offset + dataHex.length / 2 - 1}`,
    responseMode: 'plain',
    build: (s) => buildWriteData(s, dataHex, { offset }),
  }));

  return [
    ...writes,
    {
      name: 'ChangeFileSettings — activation SDM, NDEF verrouillé en écriture par K0',
      responseMode: 'full',
      build: (s) => buildChangeFileSettings(s, sdm.fileSettingsHex),
    },
    {
      name: 'ChangeKey — clé 1 = K1 (sun_secret)',
      responseMode: 'full',
      build: (s) => buildChangeKeyOther(s, '01', oldK1, newK1, keyVersion),
    },
    {
      // Réponse 9100 sans MAC : la session authentifiée par l'ancienne K0 est terminée.
      name: 'ChangeKey — clé 0 = K0 (clé maître) — EN DERNIER',
      responseMode: 'plain',
      build: (s) => buildChangeKeySame(s, '00', newK0, keyVersion),
    },
  ];
}

module.exports = {
  crc32Nxp,
  chunkFile,
  buildWriteData,
  buildChangeFileSettings,
  buildChangeKeyOther,
  buildChangeKeySame,
  programmingPlan,
};
