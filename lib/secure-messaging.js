'use strict';

// Secure Messaging EV2 (NTAG 424 DNA, mode AES), d'après NXP AN12196 §4.3, §4.4, §5.8-§6.3.
// Fonctions pures : entrées et sorties en hexadécimal, aucun accès NFC.

const crypto = require('crypto');
const { aesCmac } = require('./auth-crypto');

const BLOCK = 16;
const MAX_CMD_CTR = 0xffff;

function toBuf(hex, expectedLen, name) {
  if (typeof hex !== 'string' || !/^([0-9a-fA-F]{2})*$/.test(hex)) {
    throw new Error(`${name} : hexadécimal invalide`);
  }
  const buf = Buffer.from(hex, 'hex');
  if (expectedLen !== undefined && buf.length !== expectedLen) {
    throw new Error(`${name} : ${expectedLen} octets attendus, ${buf.length} reçus`);
  }
  return buf;
}

const toHex = (buf) => buf.toString('hex').toUpperCase();

function aesCbc(encrypt, key, iv, data) {
  if (data.length % BLOCK !== 0) throw new Error('Données non alignées sur 16 octets');
  const c = encrypt
    ? crypto.createCipheriv('aes-128-cbc', key, iv)
    : crypto.createDecipheriv('aes-128-cbc', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}

// --- Compteur de commandes ---------------------------------------------------

// CmdCtr sur 2 octets, poids faible en premier (1 → "0100").
function cmdCtrToHex(cmdCtr) {
  if (!Number.isInteger(cmdCtr) || cmdCtr < 0 || cmdCtr > MAX_CMD_CTR) {
    throw new Error(`CmdCtr invalide : ${cmdCtr}`);
  }
  const b = Buffer.alloc(2);
  b.writeUInt16LE(cmdCtr);
  return toHex(b);
}

// Incrémenté après chaque paire commande/réponse réussie. À 0xFFFF, il faut se ré-authentifier.
function nextCmdCtr(cmdCtr) {
  if (cmdCtr >= MAX_CMD_CTR) throw new Error('CmdCtr saturé : nouvelle authentification nécessaire');
  return cmdCtr + 1;
}

// --- IV de session -----------------------------------------------------------

// IV = E(SesAuthENCKey, label || TI || CmdCtr || 8 octets à zéro), label A55A (commande) ou 5AA5 (réponse).
function computeIV(encKeyHex, labelHex, tiHex, cmdCtr) {
  const key = toBuf(encKeyHex, 16, 'SesAuthENCKey');
  const input = Buffer.concat([
    toBuf(labelHex, 2, 'label'),
    toBuf(tiHex, 4, 'TI'),
    toBuf(cmdCtrToHex(cmdCtr), 2, 'CmdCtr'),
    Buffer.alloc(8),
  ]);
  return toHex(aesCbc(true, key, Buffer.alloc(BLOCK), input));
}

const ivCommand = (encKey, ti, cmdCtr) => computeIV(encKey, 'A55A', ti, cmdCtr);
// La réponse utilise le compteur déjà incrémenté par la puce (CmdCtr + 1).
const ivResponse = (encKey, ti, cmdCtr) => computeIV(encKey, '5AA5', ti, nextCmdCtr(cmdCtr));

// --- Padding ISO/IEC 9797-1 méthode 2 ------------------------------------------

// Ajoute 0x80 puis des zéros jusqu'à un multiple de 16 (toujours au moins 1 octet ajouté).
function pad(hex) {
  const data = toBuf(hex, undefined, 'données');
  const padLen = BLOCK - (data.length % BLOCK);
  const p = Buffer.alloc(padLen);
  p[0] = 0x80;
  return toHex(Buffer.concat([data, p]));
}

function unpad(hex) {
  const data = toBuf(hex, undefined, 'données');
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0x00) i--;
  if (i < 0 || data[i] !== 0x80 || data.length - i > BLOCK) throw new Error('Padding invalide');
  return toHex(data.subarray(0, i));
}

// --- Chiffrement des données ---------------------------------------------------

function encryptCommandData(encKeyHex, tiHex, cmdCtr, plainHex) {
  const iv = toBuf(ivCommand(encKeyHex, tiHex, cmdCtr), 16, 'IV');
  return toHex(aesCbc(true, toBuf(encKeyHex, 16, 'SesAuthENCKey'), iv, toBuf(pad(plainHex))));
}

function decryptResponseData(encKeyHex, tiHex, cmdCtr, encHex) {
  const iv = toBuf(ivResponse(encKeyHex, tiHex, cmdCtr), 16, 'IV');
  const plain = aesCbc(false, toBuf(encKeyHex, 16, 'SesAuthENCKey'), iv, toBuf(encHex, undefined, 'données chiffrées'));
  return unpad(toHex(plain));
}

// --- MAC -----------------------------------------------------------------------

// MACt = les 8 octets d'indice impair du CMAC (1, 3, 5 ... 15).
function truncateMac(cmacHex) {
  const m = toBuf(cmacHex, 16, 'CMAC');
  return toHex(Buffer.from([1, 3, 5, 7, 9, 11, 13, 15].map((i) => m[i])));
}

// MACt(SesAuthMACKey, Cmd || CmdCtr || TI || CmdHeader || Données)
function macCommand(macKeyHex, cmdHex, cmdCtr, tiHex, headerHex = '', dataHex = '') {
  toBuf(cmdHex, 1, 'Cmd');
  toBuf(tiHex, 4, 'TI');
  return truncateMac(aesCmac(macKeyHex, cmdHex + cmdCtrToHex(cmdCtr) + tiHex + headerHex + dataHex));
}

// MACt(SesAuthMACKey, SW2 || (CmdCtr + 1) || TI || Données de réponse)
function macResponse(macKeyHex, sw2Hex, cmdCtr, tiHex, dataHex = '') {
  toBuf(sw2Hex, 1, 'SW2');
  toBuf(tiHex, 4, 'TI');
  return truncateMac(aesCmac(macKeyHex, sw2Hex + cmdCtrToHex(nextCmdCtr(cmdCtr)) + tiHex + dataHex));
}

function verifyResponseMac(macKeyHex, sw2Hex, cmdCtr, tiHex, dataHex, receivedMacHex) {
  const expected = toBuf(macResponse(macKeyHex, sw2Hex, cmdCtr, tiHex, dataHex));
  const received = toBuf(receivedMacHex, 8, 'MACt reçu');
  return crypto.timingSafeEqual(expected, received);
}

// --- APDU ----------------------------------------------------------------------

const MODES = ['plain', 'mac', 'full'];

// session = { ti, encKey, macKey, cmdCtr }
// mode 'full' : header en clair, données chiffrées, MAC ; 'mac' : tout en clair + MAC ; 'plain' : rien.
function buildCommand(session, cmdHex, headerHex = '', dataHex = '', mode = 'full') {
  if (!MODES.includes(mode)) throw new Error(`Mode inconnu : ${mode}`);
  toBuf(cmdHex, 1, 'Cmd');
  toBuf(headerHex, undefined, 'CmdHeader');
  toBuf(dataHex, undefined, 'CmdData');

  let body = headerHex;
  if (mode === 'plain') {
    body += dataHex;
  } else {
    const payload = mode === 'full' && dataHex
      ? encryptCommandData(session.encKey, session.ti, session.cmdCtr, dataHex)
      : dataHex;
    body += payload + macCommand(session.macKey, cmdHex, session.cmdCtr, session.ti, headerHex, payload);
  }

  const lc = body.length / 2;
  if (lc > 255) throw new Error(`Commande trop longue (${lc} octets), découpage non géré`);
  const lcHex = lc ? toHex(Buffer.from([lc])) : '';
  return ('90' + cmdHex + '0000' + lcHex + body + '00').toUpperCase();
}

// Analyse une R-APDU : vérifie le MAC, déchiffre si besoin, et renvoie le CmdCtr suivant.
// Une erreur de la puce (SW ≠ 9100) n'a pas de MAC : on la renvoie telle quelle, ok = false.
function parseResponse(session, rapduHex, mode = 'full') {
  if (!MODES.includes(mode)) throw new Error(`Mode inconnu : ${mode}`);
  const r = toBuf(rapduHex, undefined, 'R-APDU');
  if (r.length < 2) throw new Error('R-APDU trop courte');
  const sw = toHex(r.subarray(-2));
  const body = toHex(r.subarray(0, -2));

  if (sw !== '9100') return { ok: false, sw, data: body, cmdCtr: session.cmdCtr };

  const nextCtr = nextCmdCtr(session.cmdCtr);
  if (mode === 'plain') return { ok: true, sw, data: body, cmdCtr: nextCtr };

  if (body.length < 16) throw new Error('Réponse sans MAC');
  const payload = body.slice(0, -16);
  const mac = body.slice(-16);
  if (!verifyResponseMac(session.macKey, sw.slice(2), session.cmdCtr, session.ti, payload, mac)) {
    throw new Error('MAC de réponse invalide : réponse altérée ou session désynchronisée');
  }
  const data = mode === 'full' && payload
    ? decryptResponseData(session.encKey, session.ti, session.cmdCtr, payload)
    : payload;
  return { ok: true, sw, data, cmdCtr: nextCtr };
}

module.exports = {
  cmdCtrToHex,
  nextCmdCtr,
  ivCommand,
  ivResponse,
  pad,
  unpad,
  encryptCommandData,
  decryptResponseData,
  truncateMac,
  macCommand,
  macResponse,
  verifyResponseMac,
  buildCommand,
  parseResponse,
};
