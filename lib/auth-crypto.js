'use strict';

// Crypto de AuthenticateEV2First (NTAG 424 DNA), d'après NXP AN12196 §5.6 / §5.10.
// Fonctions pures : entrées et sorties en hexadécimal, aucun accès NFC.

const crypto = require('crypto');

const BLOCK = 16;
const ZERO_IV = Buffer.alloc(BLOCK);

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

// AES-128-CBC sans padding (les données font toujours un multiple de 16 octets).
function aesCbc(encrypt, key, iv, data) {
  if (data.length % BLOCK !== 0) throw new Error('Données non alignées sur 16 octets');
  const c = encrypt
    ? crypto.createCipheriv('aes-128-cbc', key, iv)
    : crypto.createDecipheriv('aes-128-cbc', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}

function aesEcbBlock(key, block) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

// Doublement dans GF(2^128), utilisé pour les sous-clés CMAC.
function dbl(block) {
  const out = Buffer.alloc(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    out[i] = ((block[i] << 1) | (i + 1 < BLOCK ? block[i + 1] >> 7 : 0)) & 0xff;
  }
  if (block[0] & 0x80) out[BLOCK - 1] ^= 0x87;
  return out;
}

// AES-CMAC (RFC 4493 / NIST SP 800-38B), sortie 16 octets.
function aesCmac(keyHex, msgHex) {
  const key = toBuf(keyHex, 16, 'clé');
  const msg = toBuf(msgHex, undefined, 'message');

  const k1 = dbl(aesEcbBlock(key, Buffer.alloc(BLOCK)));
  const k2 = dbl(k1);

  const n = Math.max(1, Math.ceil(msg.length / BLOCK));
  const complete = msg.length > 0 && msg.length % BLOCK === 0;

  const last = Buffer.alloc(BLOCK);
  const tail = msg.subarray((n - 1) * BLOCK);
  tail.copy(last);
  if (!complete) last[tail.length] = 0x80;
  const sub = complete ? k1 : k2;
  for (let i = 0; i < BLOCK; i++) last[i] ^= sub[i];

  let x = Buffer.alloc(BLOCK);
  for (let b = 0; b < n - 1; b++) {
    const y = Buffer.alloc(BLOCK);
    for (let i = 0; i < BLOCK; i++) y[i] = x[i] ^ msg[b * BLOCK + i];
    x = aesEcbBlock(key, y);
  }
  for (let i = 0; i < BLOCK; i++) last[i] ^= x[i];
  return toHex(aesEcbBlock(key, last));
}

function rotateLeft(hex) {
  const b = toBuf(hex, undefined, 'données');
  return toHex(Buffer.concat([b.subarray(1), b.subarray(0, 1)]));
}

function rotateRight(hex) {
  const b = toBuf(hex, undefined, 'données');
  return toHex(Buffer.concat([b.subarray(b.length - 1), b.subarray(0, b.length - 1)]));
}

// Étape 9 : D(K, E(K, RndB)) avec IV nul.
function decryptRndB(keyHex, encRndBHex) {
  const key = toBuf(keyHex, 16, 'clé');
  return toHex(aesCbc(false, key, ZERO_IV, toBuf(encRndBHex, 16, 'E(K, RndB)')));
}

// Étape 10 : RndA aléatoire (16 octets).
function generateRndA() {
  return toHex(crypto.randomBytes(16));
}

// Étapes 11-13 : E(K, RndA || RndB') avec RndB' = RndB tourné d'un octet à gauche.
function buildPart2Payload(keyHex, rndAHex, rndBHex) {
  const key = toBuf(keyHex, 16, 'clé');
  const rndA = toBuf(rndAHex, 16, 'RndA');
  toBuf(rndBHex, 16, 'RndB');
  const rndBRot = toBuf(rotateLeft(rndBHex), 16, "RndB'");
  return toHex(aesCbc(true, key, ZERO_IV, Buffer.concat([rndA, rndBRot])));
}

// Étapes 18-24 : déchiffre la réponse de la puce et vérifie que RndA' est bien
// RndA tourné d'un octet à gauche (preuve que la puce connaît la clé).
function parsePart2Response(keyHex, encResponseHex, rndAHex) {
  const key = toBuf(keyHex, 16, 'clé');
  const plain = aesCbc(false, key, ZERO_IV, toBuf(encResponseHex, 32, 'réponse Part2'));
  const result = {
    ti: toHex(plain.subarray(0, 4)),
    rndAPrime: toHex(plain.subarray(4, 20)),
    pdCap2: toHex(plain.subarray(20, 26)),
    pcdCap2: toHex(plain.subarray(26, 32)),
  };
  if (rotateRight(result.rndAPrime) !== toHex(toBuf(rndAHex, 16, 'RndA'))) {
    throw new Error("Authentification échouée : RndA' renvoyé par la puce ne correspond pas");
  }
  return result;
}

// Étapes 25-26 : vecteur de session SV1/SV2 (32 octets).
// label || 0001 0080 || RndA[15:14] || (RndA[13:8] ⊕ RndB[15:10]) || RndB[9:0] || RndA[7:0]
// La numérotation NXP compte à rebours : [15] est le premier octet.
function buildSV(labelHex, rndAHex, rndBHex) {
  const label = toBuf(labelHex, 2, 'label');
  const a = toBuf(rndAHex, 16, 'RndA');
  const b = toBuf(rndBHex, 16, 'RndB');
  const xored = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) xored[i] = a[2 + i] ^ b[i];
  return toHex(Buffer.concat([
    label, Buffer.from('00010080', 'hex'),
    a.subarray(0, 2), xored, b.subarray(6, 16), a.subarray(8, 16),
  ]));
}

const buildSV1 = (rndA, rndB) => buildSV('A55A', rndA, rndB);
const buildSV2 = (rndA, rndB) => buildSV('5AA5', rndA, rndB);

// Étapes 27-28 : KSesAuthENC = CMAC(K, SV1), KSesAuthMAC = CMAC(K, SV2).
function deriveSessionKeys(keyHex, rndAHex, rndBHex) {
  return {
    sesAuthEncKey: aesCmac(keyHex, buildSV1(rndAHex, rndBHex)),
    sesAuthMacKey: aesCmac(keyHex, buildSV2(rndAHex, rndBHex)),
  };
}

module.exports = {
  aesCmac,
  rotateLeft,
  rotateRight,
  decryptRndB,
  generateRndA,
  buildPart2Payload,
  parsePart2Response,
  buildSV1,
  buildSV2,
  deriveSessionKeys,
};
