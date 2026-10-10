'use strict';

// Configuration SUN/SDM du fichier NDEF (NTAG 424 DNA), d'après NXP AN12196 §3, §5.7, §5.9.
// Fonctions pures : entrées et sorties en hexadécimal / chaînes, aucun accès NFC.

const { aesCmac } = require('./auth-crypto');
const { truncateMac } = require('./secure-messaging');

const NDEF_FILE_NO = '02';     // fichier NDEF (E104)
const NDEF_FILE_SIZE = 256;    // taille du fichier NDEF d'une NTAG 424 DNA
const HTTPS_PREFIX = 'https://';
const HTTPS_PREFIX_CODE = 0x04; // code d'abréviation URI NFC Forum pour "https://"

// Longueur (en caractères ASCII) de chaque miroir.
const MIRRORS = { uid: 14, ctr: 6, cmac: 16 };

// URL cible (contrat backend).
const NTV_URL_TEMPLATE =
  'https://backend-contracts-ntv.onrender.com/api/nfc/verify?uid={uid}&ctr={ctr}&cmac={cmac}';

const toHex = (buf) => buf.toString('hex').toUpperCase();

// Offset 3 octets, poids faible en premier (32 → "200000").
function offsetToHex(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffff) throw new Error(`Offset invalide : ${n}`);
  const b = Buffer.alloc(3);
  b.writeUIntLE(n, 0, 3);
  return toHex(b);
}

// --- Fichier NDEF ----------------------------------------------------------------

// Contenu du fichier NDEF pour une URL https : NLEN(2) || D1 01 PL 55 04 || reste de l'URL.
// Renvoie aussi `textStart` : position, dans le fichier, du premier caractère après "https://".
function uriNdefFile(url) {
  if (!url.startsWith(HTTPS_PREFIX)) throw new Error('L\'URL doit commencer par https://');
  const rest = Buffer.from(url.slice(HTTPS_PREFIX.length), 'ascii');
  if (rest.toString('ascii') !== url.slice(HTTPS_PREFIX.length)) throw new Error('URL non ASCII');
  const payloadLen = 1 + rest.length;
  if (payloadLen > 255) throw new Error('URL trop longue pour un enregistrement NDEF court');
  const record = Buffer.concat([Buffer.from([0xd1, 0x01, payloadLen, 0x55, HTTPS_PREFIX_CODE]), rest]);
  const nlen = Buffer.alloc(2);
  nlen.writeUInt16BE(record.length);
  const file = Buffer.concat([nlen, record]);
  if (file.length > NDEF_FILE_SIZE) throw new Error(`Fichier NDEF trop grand (${file.length} > ${NDEF_FILE_SIZE})`);
  return { fileHex: toHex(file), textStart: 2 + 5 };
}

// Remplace {uid}, {ctr}, {cmac} par des zéros ASCII et calcule la position de chacun dans le fichier.
function buildSdmNdef(template = NTV_URL_TEMPLATE) {
  const found = {};
  let url = '';
  let last = 0;
  for (const m of template.matchAll(/\{(\w+)\}/g)) {
    const name = m[1];
    if (!(name in MIRRORS)) throw new Error(`Champ miroir inconnu : {${name}}`);
    if (name in found) throw new Error(`Champ miroir en double : {${name}}`);
    url += template.slice(last, m.index);
    found[name] = url.length; // position dans l'URL
    url += '0'.repeat(MIRRORS[name]);
    last = m.index + m[0].length;
  }
  url += template.slice(last);
  for (const name of Object.keys(MIRRORS)) {
    if (!(name in found)) throw new Error(`Champ miroir manquant : {${name}}`);
  }
  if (found.cmac + MIRRORS.cmac !== url.length) {
    // Avec SDMMACInputOffset == SDMMACOffset, rien ne doit suivre le CMAC (AN12196 §3.4.1).
    throw new Error('{cmac} doit être à la toute fin de l\'URL');
  }

  const { fileHex, textStart } = uriNdefFile(url);
  const inFile = (posInUrl) => textStart + posInUrl - HTTPS_PREFIX.length;
  const offsets = {
    uidOffset: inFile(found.uid),
    sdmReadCtrOffset: inFile(found.ctr),
    sdmMacInputOffset: inFile(found.cmac),
    sdmMacOffset: inFile(found.cmac),
  };
  return { url, fileHex, length: fileHex.length / 2, offsets };
}

// --- Paramètres du fichier (Cmd.ChangeFileSettings) --------------------------------

// Données de ChangeFileSettings pour le fichier NDEF avec SDM.
// Droits d'accès : chiffre hexa 0-4 = numéro de clé, E = libre, F = interdit.
function buildFileSettings({
  commMode = 0x00,         // 00 = CommMode.Plain (le NDEF doit rester lisible par les téléphones)
  readWrite = 0x0, change = 0x0, read = 0xe, write = 0x0,
  uidMirror = true, ctrMirror = true, asciiEncoding = true,
  ctrRet = 0x1, metaRead = 0xe, fileRead = 0x1,
  uidOffset, sdmReadCtrOffset, piccDataOffset, sdmMacInputOffset, sdmMacOffset,
}) {
  const nib = (v, name) => {
    if (!Number.isInteger(v) || v < 0 || v > 0xf) throw new Error(`${name} invalide : ${v}`);
    return v;
  };
  const fileOption = 0x40 | (commMode & 0x03); // bit 6 : SDM et miroir activés
  const accessRights = Buffer.from([
    (nib(readWrite, 'RW') << 4) | nib(change, 'Change'),
    (nib(read, 'Read') << 4) | nib(write, 'Write'),
  ]);
  const sdmOptions = (uidMirror ? 0x80 : 0) | (ctrMirror ? 0x40 : 0) | (asciiEncoding ? 0x01 : 0);
  const sdmAccessRights = Buffer.from([
    0xf0 | nib(ctrRet, 'SDMCtrRet'),
    (nib(metaRead, 'SDMMetaRead') << 4) | nib(fileRead, 'SDMFileRead'),
  ]);

  let out = toHex(Buffer.from([fileOption])) + toHex(accessRights)
    + toHex(Buffer.from([sdmOptions])) + toHex(sdmAccessRights);

  // Champs conditionnels, dans l'ordre imposé par la datasheet NT4H2421.
  if (metaRead === 0xe) {
    if (uidMirror) out += offsetToHex(uidOffset);
    if (ctrMirror) out += offsetToHex(sdmReadCtrOffset);
  } else if (metaRead <= 0x4) {
    out += offsetToHex(piccDataOffset);
  }
  if (fileRead !== 0xf) {
    out += offsetToHex(sdmMacInputOffset);
    out += offsetToHex(sdmMacOffset);
  }
  return out;
}

// Configuration cible NTV : UID et compteur en clair, CMAC avec K1 (sun_secret), NDEF verrouillé par K0.
// Compteur lisible librement (SDMCtrRet = E) : il est de toute façon visible dans l'URL.
function ntvSdmConfig(template = NTV_URL_TEMPLATE) {
  const ndef = buildSdmNdef(template);
  const fileSettingsHex = buildFileSettings({ ...ndef.offsets, ctrRet: 0xe });
  return { ...ndef, fileSettingsHex };
}

// --- Vérification d'un scan (côté backend, sert ici pour la simulation) -----------

// SV2 = 3CC3 0001 0080 || UID(7) || SDMReadCtr(3, poids faible d'abord)
// Le compteur est affiché dans l'URL poids FORT d'abord ("00003D"), il faut donc l'inverser.
function sdmSessionMacKey(sunSecretHex, uidHex, ctrUrlHex) {
  if (!/^[0-9A-Fa-f]{14}$/.test(uidHex)) throw new Error('UID : 7 octets attendus');
  if (!/^[0-9A-Fa-f]{6}$/.test(ctrUrlHex)) throw new Error('Compteur : 3 octets attendus');
  const ctrLsb = toHex(Buffer.from(ctrUrlHex, 'hex').reverse());
  return aesCmac(sunSecretHex, '3CC300010080' + uidHex.toUpperCase() + ctrLsb);
}

// SDMMAC = MACt(KSesSDMFileReadMAC, entrée vide), octets impairs.
function sdmMac(sunSecretHex, uidHex, ctrUrlHex) {
  return truncateMac(aesCmac(sdmSessionMacKey(sunSecretHex, uidHex, ctrUrlHex), ''));
}

module.exports = {
  NDEF_FILE_NO,
  NTV_URL_TEMPLATE,
  offsetToHex,
  uriNdefFile,
  buildSdmNdef,
  buildFileSettings,
  ntvSdmConfig,
  sdmSessionMacKey,
  sdmMac,
};
