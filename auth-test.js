const { NFC } = require('nfc-pcsc');
const ac = require('./lib/auth-crypto');

// Test d'authentification RÉELLE (AuthenticateEV2First, AN12196 §5.6) — AUCUNE ÉCRITURE.
// Seules commandes envoyées : lecture UID, SELECT application NDEF, Auth étape 1, Auth étape 2.

const KEY_NO = '00';
const KEY = '00000000000000000000000000000000'; // clé usine (puces vierges)

const nfc = new NFC();
const hex = b => b.toString('hex').toUpperCase();

const STATUS = {
  '9000': 'OK',
  '9100': 'OK',
  '91AF': 'trame suivante attendue',
  '911C': 'commande illégale',
  '917E': 'longueur incorrecte',
  '9140': 'numéro de clé inexistant',
  '919D': 'permission refusée',
  '91AE': 'erreur d\'authentification (mauvaise clé ?)',
  '91CA': 'commande interrompue',
  '6A82': 'application/fichier introuvable',
};
const statusText = sw => STATUS[sw] || 'inconnu';

console.log('🔐 Test authentification AES (EV2First, clé 0) — AUCUNE ÉCRITURE — Ctrl+C pour quitter\n');

// Envoie une APDU, affiche l'échange, renvoie { data, sw }.
async function send(reader, label, apduHex) {
  console.log(`   > ${label}`);
  console.log(`     C-APDU : ${apduHex}`);
  const resp = await reader.transmit(Buffer.from(apduHex, 'hex'), 255);
  const data = hex(resp.slice(0, -2));
  const sw = hex(resp.slice(-2));
  console.log(`     R-APDU : ${data}${sw}  → ${sw} (${statusText(sw)})`);
  return { data, sw };
}

class AuthFailure extends Error {}

function expect(step, sw, wanted) {
  if (sw !== wanted) throw new AuthFailure(`${step} : statut ${sw} (${statusText(sw)}), attendu ${wanted}`);
}

nfc.on('reader', reader => {
  reader.autoProcessing = false;
  console.log(`✅ Lecteur : ${reader.reader.name}`);
  console.log('👉 Pose une puce...\n');

  reader.on('card', async () => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    try {
      // 1) UID
      const uid = await send(reader, 'Lecture UID', 'FFCA000000');
      expect('Lecture UID', uid.sw, '9000');
      console.log(`\n💳 UID : ${uid.data}\n`);

      // 2) SELECT application NDEF (DF name D2760000850101)
      const sel = await send(reader, 'SELECT application NDEF', '00A4040007D276000085010100');
      expect('SELECT', sel.sw, '9000');

      // 3) Auth étape 1 : 90 71 00 00 02 <KeyNo> <LenCap=00> 00 → E(K, RndB) + 91AF
      const a1 = await send(reader, `AuthenticateEV2First étape 1 (clé ${KEY_NO})`, `9071000002${KEY_NO}0000`);
      expect('Auth étape 1', a1.sw, '91AF');
      if (a1.data.length !== 32) throw new AuthFailure(`Auth étape 1 : challenge de ${a1.data.length / 2} octets, 16 attendus`);

      const rndB = ac.decryptRndB(KEY, a1.data);
      const rndA = ac.generateRndA();
      const part2 = ac.buildPart2Payload(KEY, rndA, rndB);
      console.log(`     RndB (déchiffré)        : ${rndB}`);
      console.log(`     RndA (généré)           : ${rndA}`);
      console.log(`     E(K, RndA || RndB')     : ${part2}\n`);

      // 4) Auth étape 2 : 90 AF 00 00 20 <32 octets> 00 → E(K, TI || RndA' || caps) + 9100
      const a2 = await send(reader, 'AuthenticateEV2First étape 2', `90AF000020${part2}00`);
      expect('Auth étape 2', a2.sw, '9100');
      if (a2.data.length !== 64) throw new AuthFailure(`Auth étape 2 : réponse de ${a2.data.length / 2} octets, 32 attendus`);

      // 5) Vérification RndA' + dérivation des clés de session (lève une erreur si RndA' faux)
      let res;
      try {
        res = ac.parsePart2Response(KEY, a2.data, rndA);
      } catch (e) {
        throw new AuthFailure(e.message);
      }
      const keys = ac.deriveSessionKeys(KEY, rndA, rndB);

      console.log(`     RndA' (reçu)            : ${res.rndAPrime}  ✔ correspond à RndA tourné`);
      console.log(`     PDcap2 / PCDcap2        : ${res.pdCap2} / ${res.pcdCap2}`);
      console.log('\n✅ AUTHENTIFICATION RÉUSSIE');
      console.log(`   UID            : ${uid.data}`);
      console.log(`   TI             : ${res.ti}`);
      console.log(`   SesAuthENCKey  : ${keys.sesAuthEncKey}`);
      console.log(`   SesAuthMACKey  : ${keys.sesAuthMacKey}`);
    } catch (err) {
      if (err instanceof AuthFailure) {
        console.log(`\n❌ ÉCHEC : ${err.message}`);
      } else {
        console.log(`\n❌ ÉCHEC (erreur de communication) : ${err.message}`);
      }
    }
    console.log('   (aucune écriture effectuée)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  });

  reader.on('card.off', () => console.log('   (puce retirée)\n'));
  reader.on('error', err => console.error(`⚠️ Erreur lecteur : ${err.message}`));
});

nfc.on('error', err => console.error(`⚠️ Erreur NFC : ${err.message}`));
