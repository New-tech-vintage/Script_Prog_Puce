const { NFC } = require('nfc-pcsc');
const ac = require('./lib/auth-crypto');
const sm = require('./lib/secure-messaging');

// Test du Secure Messaging sur vraie puce — LECTURE SEULE.
// AuthenticateEV2First (clé 0) puis GetCardUID (CommMode.FULL), comparé à l'UID lu en clair.

const KEY_NO = '00';
const KEY = '00000000000000000000000000000000'; // clé usine (puces vierges)

// Seuls préfixes d'APDU autorisés à partir vers la puce. Tout le reste est bloqué AVANT envoi.
const ALLOWED = {
  FFCA: 'lecture UID (lecteur)',
  '00A4': 'SELECT',
  '9071': 'AuthenticateEV2First étape 1',
  '90AF': 'AuthenticateEV2First étape 2',
  '9051': 'GetCardUID',
};

const nfc = new NFC();
const hex = b => b.toString('hex').toUpperCase();

const STATUS = {
  '9000': 'OK',
  '9100': 'OK',
  '91AF': 'trame suivante attendue',
  '911C': 'commande illégale',
  '911E': 'erreur d\'intégrité (MAC/CRC)',
  '917E': 'longueur incorrecte',
  '9140': 'numéro de clé inexistant',
  '919D': 'permission refusée',
  '91AE': 'erreur d\'authentification',
  '91CA': 'commande interrompue',
  '6A82': 'application/fichier introuvable',
};
const statusText = sw => STATUS[sw] || 'inconnu';

class TestFailure extends Error {}

console.log('🔒 Test Secure Messaging (Auth clé 0 + GetCardUID chiffré) — LECTURE SEULE — Ctrl+C pour quitter\n');

// Envoie une APDU (après contrôle de la liste blanche), affiche l'échange, renvoie la réponse brute en hex.
async function send(reader, label, apduHex) {
  const prefix = apduHex.slice(0, 4).toUpperCase();
  if (!ALLOWED[prefix]) throw new Error(`APDU bloquée (hors liste blanche lecture seule) : ${apduHex}`);
  console.log(`   > ${label}`);
  console.log(`     C-APDU : ${apduHex}`);
  const resp = hex(await reader.transmit(Buffer.from(apduHex, 'hex'), 255));
  const sw = resp.slice(-4);
  console.log(`     R-APDU : ${resp}  → ${sw} (${statusText(sw)})`);
  return resp;
}

const split = resp => ({ data: resp.slice(0, -4), sw: resp.slice(-4) });

function expect(step, sw, wanted) {
  if (sw !== wanted) throw new TestFailure(`${step} : statut ${sw} (${statusText(sw)}), attendu ${wanted}`);
}

async function authenticate(reader) {
  const a1 = split(await send(reader, `AuthenticateEV2First étape 1 (clé ${KEY_NO})`, `9071000002${KEY_NO}0000`));
  expect('Auth étape 1', a1.sw, '91AF');
  if (a1.data.length !== 32) throw new TestFailure(`Auth étape 1 : challenge de ${a1.data.length / 2} octets, 16 attendus`);

  const rndB = ac.decryptRndB(KEY, a1.data);
  const rndA = ac.generateRndA();
  const part2 = ac.buildPart2Payload(KEY, rndA, rndB);

  const a2 = split(await send(reader, 'AuthenticateEV2First étape 2', `90AF000020${part2}00`));
  expect('Auth étape 2', a2.sw, '9100');
  if (a2.data.length !== 64) throw new TestFailure(`Auth étape 2 : réponse de ${a2.data.length / 2} octets, 32 attendus`);

  let res;
  try {
    res = ac.parsePart2Response(KEY, a2.data, rndA);
  } catch (e) {
    throw new TestFailure(e.message);
  }
  const keys = ac.deriveSessionKeys(KEY, rndA, rndB);
  return { ti: res.ti, encKey: keys.sesAuthEncKey, macKey: keys.sesAuthMacKey, cmdCtr: 0 };
}

nfc.on('reader', reader => {
  reader.autoProcessing = false;
  console.log(`✅ Lecteur : ${reader.reader.name}`);
  console.log('👉 Pose une puce...\n');

  reader.on('card', async () => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      // 1) UID en clair
      const u = split(await send(reader, 'Lecture UID (en clair)', 'FFCA000000'));
      expect('Lecture UID', u.sw, '9000');
      const plainUid = u.data;
      console.log(`\n💳 UID en clair : ${plainUid}\n`);

      // 2) SELECT application NDEF
      const sel = split(await send(reader, 'SELECT application NDEF', '00A4040007D276000085010100'));
      expect('SELECT', sel.sw, '9000');

      // 3) Authentification
      const session = await authenticate(reader);
      console.log('\n   🔑 Session ouverte');
      console.log(`     TI            : ${session.ti}`);
      console.log(`     SesAuthENCKey : ${session.encKey}`);
      console.log(`     SesAuthMACKey : ${session.macKey}`);
      console.log(`     CmdCtr        : ${session.cmdCtr}\n`);

      // 4) GetCardUID en CommMode.FULL (commande 51, ni header ni données → MAC seul)
      const apdu = sm.buildCommand(session, '51', '', '', 'full');
      const resp = await send(reader, `GetCardUID (Secure Messaging, CmdCtr = ${session.cmdCtr})`, apdu);

      let parsed;
      try {
        parsed = sm.parseResponse(session, resp, 'full');
      } catch (e) {
        throw new TestFailure(`GetCardUID : ${e.message}`);
      }
      if (!parsed.ok) throw new TestFailure(`GetCardUID : statut ${parsed.sw} (${statusText(parsed.sw)})`);
      session.cmdCtr = parsed.cmdCtr;
      console.log('     MAC de réponse : ✔ vérifié');
      console.log(`     UID déchiffré  : ${parsed.data}`);
      console.log(`     CmdCtr         : ${session.cmdCtr}`);

      // 5) Comparaison
      if (parsed.data !== plainUid) {
        throw new TestFailure(`UID chiffré (${parsed.data}) ≠ UID clair (${plainUid})`);
      }
      console.log('\n✅ SECURE MESSAGING VALIDÉ SUR VRAIE PUCE — UID chiffré = UID clair');
      console.log(`   UID : ${plainUid}`);
    } catch (err) {
      const kind = err instanceof TestFailure ? '' : ' (erreur de communication ou interne)';
      console.log(`\n❌ ÉCHEC${kind} : ${err.message}`);
    }
    console.log('   (aucune écriture effectuée)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  });

  reader.on('card.off', () => console.log('   (puce retirée)\n'));
  reader.on('error', err => console.error(`⚠️ Erreur lecteur : ${err.message}`));
});

nfc.on('error', err => console.error(`⚠️ Erreur NFC : ${err.message}`));
