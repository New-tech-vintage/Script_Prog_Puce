const { NFC } = require('nfc-pcsc');
const ac = require('./lib/auth-crypto');
const sdm = require('./lib/sdm-config');
const prog = require('./lib/programmer');

// Diagnostic de la taille maximale d'APDU avec l'ACR122U, sur puce VIERGE (écriture NDEF libre).
// Écrit le DÉBUT du vrai fichier NDEF NTV (mêmes octets que program.js écrira ensuite) à l'offset 0,
// avec des tailles croissantes, puis relit avec des tailles croissantes.
// Ne touche ni aux clés ni aux paramètres de fichier.
//
//   node write-test.js         → WriteData sans authentification (accès libre E)
//   node write-test.js --auth  → idem après AuthenticateEV2First avec la clé 0 usine

const WITH_AUTH = process.argv.includes('--auth');
const ZERO_KEY = '00'.repeat(16);

// Tailles de données testées. APDU WriteData = 13 + n octets (90 8D 00 00 Lc | 7 octets de header | n | 00).
// n = 34 donne une APDU de 47 octets, la taille de ChangeKey et ChangeFileSettings.
const WRITE_SIZES = [8, 16, 24, 32, 34, 40, 48, 56, 64, 80, 96, 108];
const READ_SIZES = [16, 32, 48, 64, 96, 108];

const ALLOWED = {
  FFCA: 'lecture UID',
  '00A4': 'SELECT',
  '00B0': 'ReadBinary',
  '9071': 'Auth étape 1',
  '90AF': 'Auth étape 2',
  '908D': 'WriteData (fichier NDEF uniquement)',
};

const nfc = new NFC();
const hex = b => b.toString('hex').toUpperCase();
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Mêmes réglages que program.js : délai après détection, retry sur la seule lecture UID,
// tampons de réponse éprouvés (12 pour l'UID, 255 sinon).
const CARD_SETTLE_MS = 200;
const UID_RETRY_DELAYS_MS = [200, 400, 600];

class TransmitFailure extends Error {}

async function send(reader, label, apduHex, quiet = false) {
  const prefix = apduHex.slice(0, 4);
  if (!ALLOWED[prefix]) throw new Error(`APDU bloquée : ${apduHex}`);
  // Garde-fou : WriteData uniquement sur le fichier 02 (NDEF).
  if (prefix === '908D' && apduHex.slice(10, 12) !== '02') throw new Error(`WriteData hors fichier NDEF bloqué : ${apduHex}`);
  if (!quiet) {
    console.log(`   > ${label}`);
    console.log(`     C-APDU (${apduHex.length / 2} o) : ${apduHex}`);
  }
  let resp;
  try {
    resp = hex(await reader.transmit(Buffer.from(apduHex, 'hex'), prefix === 'FFCA' ? 12 : 255));
  } catch (e) {
    const detail = e.previous ? ` [${e.previous.message}]` : '';
    throw new TransmitFailure(`${e.message}${detail}`);
  }
  if (!quiet) console.log(`     R-APDU (${resp.length / 2} o) : ${resp}`);
  return { data: resp.slice(0, -4), sw: resp.slice(-4) };
}

// Reconnexion en mode EXCLUSIF (voir program.js) : refuse de démarrer si un autre programme
// (read-uid.js dans un autre terminal, par ex.) est connecté au lecteur.
async function lockReaderExclusive(reader) {
  const r = reader.reader;
  await reader.disconnect();
  const protocol = await new Promise((resolve, reject) => {
    r.connect({ share_mode: r.SCARD_SHARE_EXCLUSIVE }, (err, proto) => (err ? reject(err) : resolve(proto)));
  }).catch(err => {
    throw new Error(String(err.message).toLowerCase().includes('8010000b')
      ? 'le lecteur est utilisé par un autre programme (read-uid.js… dans un autre terminal ?). Ferme-le (Ctrl+C) puis relance.'
      : `connexion exclusive impossible : ${err.message}`);
  });
  reader.connection = { type: r.SCARD_SHARE_EXCLUSIVE, protocol };
  console.log('   🔒 Lecteur réservé en mode exclusif\n');
}

// Lecture UID rejouée en cas d'erreur de transmission uniquement (jamais une écriture).
async function readUidWithRetry(reader, isCardPresent) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await send(reader, attempt ? `Lecture UID (tentative ${attempt + 1})` : 'Lecture UID', 'FFCA000000');
    } catch (e) {
      if (!(e instanceof TransmitFailure) || attempt >= UID_RETRY_DELAYS_MS.length) throw e;
      const wait = UID_RETRY_DELAYS_MS[attempt];
      console.log(`     ⚠️ ${e.message} — nouvel essai dans ${wait} ms`);
      await sleep(wait);
      if (!isCardPresent()) throw new Error('puce retirée');
    }
  }
}

async function authenticate(reader) {
  const a1 = await send(reader, 'Auth clé 0 usine — étape 1', '9071000002000000');
  if (a1.sw !== '91AF') throw new Error(`Auth étape 1 : ${a1.sw}`);
  const rndB = ac.decryptRndB(ZERO_KEY, a1.data);
  const rndA = ac.generateRndA();
  const a2 = await send(reader, 'Auth clé 0 usine — étape 2', `90AF000020${ac.buildPart2Payload(ZERO_KEY, rndA, rndB)}00`);
  if (a2.sw !== '9100') throw new Error(`Auth étape 2 : ${a2.sw}`);
  ac.parsePart2Response(ZERO_KEY, a2.data, rndA);
  console.log('     ✔ authentifié\n');
}

// Essaie chaque taille par ordre croissant ; s'arrête au premier échec (le lien peut être cassé ensuite).
async function probe(title, sizes, attempt) {
  console.log(`\n── ${title} ──`);
  const results = [];
  for (const n of sizes) {
    try {
      const { apduLen, sw, ok } = await attempt(n);
      results.push({ n, apduLen, result: ok ? `✅ ${sw}` : `⚠️ ${sw}` });
      if (!ok) break;
    } catch (e) {
      if (!(e instanceof TransmitFailure)) throw e;
      results.push({ n, apduLen: null, result: `❌ ${e.message}` });
      break;
    }
  }
  for (const r of results) {
    console.log(`   ${String(r.n).padStart(3)} octets de données${r.apduLen ? ` (APDU ${r.apduLen} o)` : ''} : ${r.result}`);
  }
  const passed = results.filter(r => r.result.startsWith('✅')).map(r => r.n);
  return passed.length ? Math.max(...passed) : 0;
}

nfc.on('reader', reader => {
  reader.autoProcessing = false;
  console.log(`✅ Lecteur : ${reader.reader.name}`);
  console.log(`👉 Pose une puce VIERGE... (mode ${WITH_AUTH ? 'avec' : 'sans'} authentification)\n`);
  let busy = false;
  let present = false;

  reader.on('card.off', () => { present = false; });

  reader.on('card', async () => {
    present = true;
    if (busy) return;
    busy = true;
    const ndef = sdm.ntvSdmConfig().fileHex;
    await sleep(CARD_SETTLE_MS); // laisse le lecteur finir l'activation de la carte
    try {
      await lockReaderExclusive(reader);
      const uid = await readUidWithRetry(reader, () => present);
      console.log(`\n💳 UID : ${uid.data}\n`);
      const sel = await send(reader, 'SELECT application NDEF', '00A4040007D276000085010100');
      if (sel.sw !== '9000') throw new Error(`SELECT : ${sel.sw}`);
      if (WITH_AUTH) await authenticate(reader);

      // Le CmdCtr n'est pas utilisé : en mode Plain, WriteData ne porte ni MAC ni chiffrement.
      const plain = { ti: '00000000', encKey: ZERO_KEY, macKey: ZERO_KEY, cmdCtr: 0 };
      const maxWrite = await probe('WriteData (fichier NDEF, offset 0)', WRITE_SIZES, async n => {
        const apdu = prog.buildWriteData(plain, ndef.slice(0, n * 2));
        const r = await send(reader, `WriteData ${n} octets`, apdu, true);
        return { apduLen: apdu.length / 2, sw: r.sw, ok: r.sw === '9100' };
      });

      let maxRead = 0;
      const selFile = await send(reader, 'SELECT fichier NDEF E104', '00A4000C02E10400', true);
      if (selFile.sw === '9000') {
        maxRead = await probe('ReadBinary (fichier NDEF, offset 0)', READ_SIZES, async n => {
          const r = await send(reader, `ReadBinary ${n} octets`, `00B00000${n.toString(16).padStart(2, '0').toUpperCase()}`, true);
          const ok = r.sw === '9000' && r.data.length === n * 2;
          return { apduLen: 5, sw: `${r.sw}, ${r.data.length / 2} o reçus`, ok };
        });
      } else {
        console.log(`\n   (SELECT E104 : ${selFile.sw}, lecture non testée)`);
      }

      console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`📏 Écriture : plus grand bloc accepté = ${maxWrite} octets (APDU ${maxWrite ? maxWrite + 13 : '-'} o)`);
      console.log(`📏 Lecture  : plus grand bloc reçu   = ${maxRead} octets`);
      if (maxWrite >= 108) console.log('   → la taille n\'est PAS en cause pour l\'écriture.');
      else console.log(`   → limite d'écriture confirmée. Fragmenter WriteData à ≤ ${maxWrite} octets.`);
      if (maxWrite < 34) console.log('   ⚠️ ChangeKey / ChangeFileSettings (APDU 47 o) risquent AUSSI d\'échouer.');
      console.log('   Clés et paramètres de fichier : inchangés. Le NDEF contient le début de l\'URL NTV.');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    } catch (e) {
      console.log(`\n❌ ${e.message}`);
      process.exitCode = 1;
    }
    process.exit();
  });

  reader.on('error', err => console.error(`⚠️ Erreur lecteur : ${err.message}`));
});

nfc.on('error', err => console.error(`⚠️ Erreur NFC : ${err.message}`));
