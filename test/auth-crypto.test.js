'use strict';

// Tests de lib/auth-crypto.js contre les vecteurs officiels NXP AN12196 (Rev. 2.0) :
//   §5.6  (Table 14) AuthenticateEV2First avec la clé 0x00
//   §5.10 (Table 19) AuthenticateEV2First avec la clé 0x03
// et contre les vecteurs AES-CMAC de la RFC 4493.

const test = require('node:test');
const assert = require('node:assert/strict');
const ac = require('../lib/auth-crypto');

const VECTORS = [
  {
    name: 'AN12196 §5.6 — clé 0x00',
    key: '00000000000000000000000000000000',
    encRndB: 'A04C124213C186F22399D33AC2A30215',
    rndB: 'B9E2FC789B64BF237CCCAA20EC7E6E48',
    rndA: '13C5DB8A5930439FC3DEF9A4C675360F',
    rndBRot: 'E2FC789B64BF237CCCAA20EC7E6E48B9',
    part2: '35C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D',
    response: '3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663',
    ti: '9D00C4DF',
    rndAPrime: 'C5DB8A5930439FC3DEF9A4C675360F13',
    sv1: 'A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F',
    sv2: '5AA50001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F',
    sesEnc: '1309C877509E5A215007FF0ED19CA564',
    sesMac: '4C6626F5E72EA694202139295C7A7FC7',
  },
  {
    name: 'AN12196 §5.10 — clé 0x03',
    key: '00000000000000000000000000000000',
    encRndB: 'B875CEB0E66A6C5CD00898DC371F92D1',
    rndB: '91517975190DCEA6104948EFA3085C1B',
    rndA: 'B98F4C50CF1C2E084FD150E33992B048',
    rndBRot: '517975190DCEA6104948EFA3085C1B91',
    part2: 'FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B1',
    response: '0CC9A8094A8EEA683ECAAC5C7BF20584206D0608D477110FC6B3D5D3F65C3A6A',
    ti: '7614281A',
    rndAPrime: '8F4C50CF1C2E084FD150E33992B048B9',
    sv1: 'A55A00010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048',
    sv2: '5AA500010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048',
    sesEnc: '7A93D6571E4B180FCA6AC90C9A7488D4',
    sesMac: 'FC4AF159B62E549B5812394CAB1918CC',
  },
];

for (const v of VECTORS) {
  test(v.name, async (t) => {
    await t.test('étape 9 : déchiffrement de RndB', () => {
      assert.equal(ac.decryptRndB(v.key, v.encRndB), v.rndB);
    });
    await t.test("étape 11 : RndB' = rotation à gauche", () => {
      assert.equal(ac.rotateLeft(v.rndB), v.rndBRot);
    });
    await t.test("étape 13 : E(K, RndA || RndB')", () => {
      assert.equal(ac.buildPart2Payload(v.key, v.rndA, v.rndB), v.part2);
    });
    await t.test('étapes 18-24 : réponse de la puce (TI, RndA\', caps)', () => {
      assert.deepEqual(ac.parsePart2Response(v.key, v.response, v.rndA), {
        ti: v.ti,
        rndAPrime: v.rndAPrime,
        pdCap2: '000000000000',
        pcdCap2: '000000000000',
      });
    });
    await t.test('étapes 25-26 : SV1 et SV2', () => {
      assert.equal(ac.buildSV1(v.rndA, v.rndB), v.sv1);
      assert.equal(ac.buildSV2(v.rndA, v.rndB), v.sv2);
    });
    await t.test('étapes 27-28 : SesAuthENCKey et SesAuthMACKey', () => {
      assert.deepEqual(ac.deriveSessionKeys(v.key, v.rndA, v.rndB), {
        sesAuthEncKey: v.sesEnc,
        sesAuthMacKey: v.sesMac,
      });
    });
  });
}

test('rejet si la puce renvoie un mauvais RndA\'', () => {
  const v = VECTORS[0];
  const wrongRndA = '00' + v.rndA.slice(2);
  assert.throws(() => ac.parsePart2Response(v.key, v.response, wrongRndA), /Authentification échouée/);
});

test('rotateRight est l\'inverse de rotateLeft', () => {
  const v = VECTORS[0];
  assert.equal(ac.rotateRight(v.rndAPrime), v.rndA);
});

test('generateRndA : 16 octets aléatoires', () => {
  const a = ac.generateRndA();
  assert.match(a, /^[0-9A-F]{32}$/);
  assert.notEqual(a, ac.generateRndA());
});

test('AES-CMAC — vecteurs RFC 4493', () => {
  const key = '2B7E151628AED2A6ABF7158809CF4F3C';
  const msg = '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51'
    + '30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710';
  assert.equal(ac.aesCmac(key, ''), 'BB1D6929E95937287FA37D129B756746');
  assert.equal(ac.aesCmac(key, msg.slice(0, 32)), '070A16B46B4D4144F79BDD9DD04A287C');
  assert.equal(ac.aesCmac(key, msg.slice(0, 80)), 'DFA66747DE9AE63030CA32611497C827');
  assert.equal(ac.aesCmac(key, msg), '51F0BEBF7E3B9D92FC49741779363CFE');
});

test('validation des entrées', () => {
  assert.throws(() => ac.decryptRndB('00', 'A04C124213C186F22399D33AC2A30215'), /16 octets attendus/);
  assert.throws(() => ac.decryptRndB('ZZ'.repeat(16), 'A04C124213C186F22399D33AC2A30215'), /hexadécimal invalide/);
});
