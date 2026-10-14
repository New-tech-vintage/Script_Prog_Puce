const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { NFC } = require('nfc-pcsc');
const ac = require('./lib/auth-crypto');
const sm = require('./lib/secure-messaging');
const sdm = require('./lib/sdm-config');
const prog = require('./lib/programmer');
const api = require('./lib/admin-api');
const { ask, askHidden } = require('./lib/prompt');

// Programmation SUN/SDM d'une NTAG 424 DNA vierge, puis liaison à un exemplaire.
//   node program.js                  → DRY-RUN (par défaut) : lit l'état, calcule et affiche le plan, N'ÉCRIT RIEN.
//   node program.js --execute        → connexion admin, choix item/taille/couleur, puis pour chaque puce :
//                                      plan, "OUI", programmation, vérification, liaison (link-chip).
//   node program.js --link-only UID  → lie une puce DÉJÀ programmée (keys-UID.json), sans lecteur.
//   --chunk=N                        → taille max (octets) de chaque WriteData / ReadBinary (défaut 32).
// Le sun_secret (K1), K0 et le mot de passe ne sont JAMAIS affichés : seul keys-<UID>.json les contient.

const EXECUTE = process.argv.includes('--execute');
const linkOnlyIdx = process.argv.indexOf('--link-only');
const LINK_ONLY_UID = linkOnlyIdx >= 0 ? (process.argv[linkOnlyIdx + 1] || '').toUpperCase() : null;
const ZERO_KEY = '00'.repeat(16);

// L'ACR122U échoue sur les grosses APDU : l'URL NDEF est écrite (et relue) par fragments.
const chunkArg = process.argv.find(a => a.startsWith('--chunk='));
const CHUNK_SIZE = chunkArg ? Number(chunkArg.slice('--chunk='.length)) : 32;
if (!Number.isInteger(CHUNK_SIZE) || CHUNK_SIZE < 8 || CHUNK_SIZE > 128) {
  console.error(`❌ --chunk invalide : ${chunkArg} (entier entre 8 et 128 attendu)`);
  process.exit(1);
}

// --- Liste blanche d'APDU, figée au démarrage selon le mode -------------------------
const READ_APDUS = {
  FFCA: 'lecture UID (lecteur)',
  '00A4': 'SELECT',
  '00B0': 'ReadBinary (lecture NDEF)',
  '9071': 'AuthenticateEV2First étape 1',
  '90AF': 'AuthenticateEV2First étape 2',
  '90F5': 'GetFileSettings',
};
const WRITE_APDUS = {
  '908D': 'WriteData',
  '905F': 'ChangeFileSettings',
  '90C4': 'ChangeKey',
};
const ALLOWED = Object.freeze(EXECUTE ? { ...READ_APDUS, ...WRITE_APDUS } : { ...READ_APDUS });

// --- K0 depuis .env --------------------------------------------------------------
function loadEnv() {
  try {
    process.loadEnvFile(path.join(__dirname, '.env'));
  } catch (e) {
    throw new Error(`.env illisible : ${e.message}`);
  }
}

function loadK0() {
  loadEnv();
  const k0 = (process.env.MASTER_KEY_K0 || '').trim().toUpperCase();
  if (!/^[0-9A-F]{32}$/.test(k0)) throw new Error('MASTER_KEY_K0 absente ou invalide dans .env (32 caractères hex attendus)');
  if (k0 === ZERO_KEY) throw new Error('MASTER_KEY_K0 ne doit pas être la clé usine (zéros)');
  return k0;
}

const HIDDEN = '«masquée — voir keys-<UID>.json»';

// --- Échanges avec la puce ---------------------------------------------------------
const hex = b => b.toString('hex').toUpperCase();
const STATUS = {
  '9000': 'OK', '9100': 'OK', '91AF': 'trame suivante attendue',
  '911C': 'commande illégale', '911E': 'erreur d\'intégrité (MAC/CRC)', '917E': 'longueur incorrecte',
  '9140': 'numéro de clé inexistant', '919D': 'permission refusée', '91AE': 'erreur d\'authentification',
  '91BE': 'hors limites du fichier', '91CA': 'commande interrompue', '91F0': 'fichier inexistant',
  '6A82': 'application/fichier introuvable', '6982': 'accès refusé',
};
const statusText = sw => STATUS[sw] || 'inconnu';

class StepFailure extends Error {
  constructor(step, message) {
    super(message);
    this.step = step;
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Délai entre la détection de la carte et la première transaction (ACR122U + nfc-pcsc).
const CARD_SETTLE_MS = 200;
// Nouvelles tentatives pour la SEULE lecture UID initiale. Jamais pour une écriture.
const UID_RETRY_DELAYS_MS = [200, 400, 600];
// Tampon de réponse : mêmes valeurs que read-uid.js / sm-test.js, éprouvées sur la vraie puce.
// (Nos réponses font au plus 34 octets ; une réponse APDU courte ne dépasse jamais 256 + 2.)
const UID_RESP_MAX = 12;
const RESP_MAX = 255;

function makeLink(reader) {
  return async function send(label, apduHex) {
    const prefix = apduHex.slice(0, 4).toUpperCase();
    if (!ALLOWED[prefix]) {
      throw new StepFailure(label, `APDU bloquée par la liste blanche (${EXECUTE ? 'execute' : 'dry-run'}) : ${apduHex}`);
    }
    console.log(`   > ${label}`);
    console.log(`     C-APDU : ${apduHex}`);
    const max = prefix === 'FFCA' ? UID_RESP_MAX : RESP_MAX;
    const resp = hex(await reader.transmit(Buffer.from(apduHex, 'hex'), max));
    const sw = resp.slice(-4);
    console.log(`     R-APDU : ${resp}  → ${sw} (${statusText(sw)})`);
    return resp;
  };
}

// nfc-pcsc se connecte à la carte en mode PARTAGÉ : si un autre programme (read-uid.js lancé dans
// un autre terminal, par ex.) est aussi connecté, les deux envoient leurs commandes en même temps
// et l'ACR122U répond "Transaction failed (0x80100016)". Pire : au milieu d'une programmation, une
// commande étrangère casserait la session sécurisée. On se reconnecte donc en mode EXCLUSIF.
const SCARD_E_SHARING_VIOLATION = 0x8010000b;

async function lockReaderExclusive(reader) {
  const r = reader.reader;
  await reader.disconnect(); // SCARD_LEAVE_CARD : la carte n'est pas réinitialisée
  const protocol = await new Promise((resolve, reject) => {
    r.connect({ share_mode: r.SCARD_SHARE_EXCLUSIVE }, (err, proto) => (err ? reject(err) : resolve(proto)));
  }).catch(err => {
    const busy = String(err.message).toLowerCase().includes(SCARD_E_SHARING_VIOLATION.toString(16));
    throw new StepFailure('Connexion exclusive au lecteur', busy
      ? 'le lecteur est utilisé par un autre programme (read-uid.js, check-state.js… dans un autre terminal ?). Ferme-le (Ctrl+C) puis relance.'
      : `connexion exclusive impossible : ${err.message}`);
  });
  reader.connection = { type: r.SCARD_SHARE_EXCLUSIVE, protocol };
  console.log('   🔒 Lecteur réservé en mode exclusif\n');
}

// Établit le contact : lecture UID (commande du lecteur, rien n'est écrit sur la puce),
// rejouée en cas d'ERREUR DE TRANSMISSION uniquement, avec un délai croissant.
async function readUidWithRetry(send, isCardPresent) {
  for (let attempt = 0; ; attempt++) {
    try {
      return split(await send(attempt ? `Lecture UID (tentative ${attempt + 1})` : 'Lecture UID', 'FFCA000000'));
    } catch (e) {
      if (e instanceof StepFailure) throw e;
      if (attempt >= UID_RETRY_DELAYS_MS.length) {
        throw new StepFailure('Lecture UID', `${e.message} — lecteur instable : retire/repose la puce, ou débranche/rebranche le lecteur`);
      }
      const wait = UID_RETRY_DELAYS_MS[attempt];
      console.log(`     ⚠️ ${e.message} — nouvel essai dans ${wait} ms`);
      await sleep(wait);
      if (!isCardPresent()) throw new StepFailure('Lecture UID', 'puce retirée');
    }
  }
}

const split = resp => ({ data: resp.slice(0, -4), sw: resp.slice(-4) });

function expect(step, sw, wanted) {
  if (sw !== wanted) throw new StepFailure(step, `statut ${sw} (${statusText(sw)}), attendu ${wanted}`);
}

async function authenticate(send, keyNo, key, label) {
  const step = `Authentification ${label}`;
  const a1 = split(await send(`${step} — étape 1`, `9071000002${keyNo}0000`));
  expect(step, a1.sw, '91AF');
  if (a1.data.length !== 32) throw new StepFailure(step, `challenge de ${a1.data.length / 2} octets, 16 attendus`);
  const rndB = ac.decryptRndB(key, a1.data);
  const rndA = ac.generateRndA();
  const a2 = split(await send(`${step} — étape 2`, `90AF000020${ac.buildPart2Payload(key, rndA, rndB)}00`));
  expect(step, a2.sw, '9100');
  if (a2.data.length !== 64) throw new StepFailure(step, `réponse de ${a2.data.length / 2} octets, 32 attendus`);
  let res;
  try {
    res = ac.parsePart2Response(key, a2.data, rndA);
  } catch (e) {
    throw new StepFailure(step, e.message);
  }
  const keys = ac.deriveSessionKeys(key, rndA, rndB);
  return { ti: res.ti, encKey: keys.sesAuthEncKey, macKey: keys.sesAuthMacKey, cmdCtr: 0 };
}

// Envoie une commande en Secure Messaging et met à jour le CmdCtr de la session.
async function smExchange(send, session, label, apdu, responseMode) {
  const resp = await send(label, apdu);
  let r;
  try {
    r = sm.parseResponse(session, resp, responseMode);
  } catch (e) {
    throw new StepFailure(label, e.message);
  }
  if (!r.ok) throw new StepFailure(label, `statut ${r.sw} (${statusText(r.sw)})`);
  session.cmdCtr = r.cmdCtr;
  return r.data;
}

// --- Contrôle « puce vierge » à partir de GetFileSettings -----------------------------
// Réglages usine du fichier NDEF : SDM désactivé, CommMode.Plain, écriture libre (E), Change = clé 0.
function checkFactoryFileSettings(dataHex, neededSize) {
  const b = Buffer.from(dataHex, 'hex');
  if (b.length < 7) throw new StepFailure('GetFileSettings', `réponse trop courte (${b.length} octets)`);
  const st = {
    fileType: b[0],
    fileOption: b[1],
    rw: b[2] >> 4, change: b[2] & 0xf, read: b[3] >> 4, write: b[3] & 0xf,
    size: b.readUIntLE(4, 3),
  };
  console.log(`     FileType ${st.fileType.toString(16).padStart(2, '0')}  FileOption ${st.fileOption.toString(16).padStart(2, '0')}`
    + `  Droits RW=${st.rw.toString(16).toUpperCase()} Change=${st.change.toString(16).toUpperCase()}`
    + ` Read=${st.read.toString(16).toUpperCase()} Write=${st.write.toString(16).toUpperCase()}  Taille ${st.size}`);
  const problems = [];
  if (st.fileOption & 0x40) problems.push('SDM déjà activé');
  if ((st.fileOption & 0x03) !== 0) problems.push('fichier NDEF pas en CommMode.Plain');
  if (st.write !== 0xe) problems.push('écriture du NDEF déjà verrouillée');
  if (st.change !== 0x0) problems.push('droit Change ≠ clé 0');
  if (st.size < neededSize) problems.push(`fichier trop petit (${st.size} < ${neededSize})`);
  if (problems.length) {
    throw new StepFailure('Contrôle puce vierge', `réglages non usine : ${problems.join(', ')}`);
  }
}

// --- Vérification finale : lecture du NDEF comme un téléphone, puis contrôle du CMAC ----
async function verifySun(send, uid, k1, cfg) {
  const step = 'Vérification SUN';
  expect(step, split(await send('SELECT application NDEF (fin de session)', '00A4040007D276000085010100')).sw, '9000');
  expect(step, split(await send('SELECT fichier NDEF E104', '00A4000C02E10400')).sw, '9000');
  // ReadBinary par fragments : 00 B0 <offset sur 2 octets> <Le>.
  let data = '';
  for (let off = 0; off < cfg.length; off += CHUNK_SIZE) {
    const n = Math.min(CHUNK_SIZE, cfg.length - off);
    const p = off.toString(16).padStart(4, '0').toUpperCase();
    const le = n.toString(16).padStart(2, '0').toUpperCase();
    const r = split(await send(`ReadBinary NDEF octets ${off}-${off + n - 1}`, `00B0${p}${le}`));
    expect(step, r.sw, '9000');
    data += r.data;
  }
  const file = Buffer.from(data, 'hex');
  const nlen = file.readUInt16BE(0);
  const url = new URL('https://' + file.subarray(7, 2 + nlen).toString('ascii'));
  const got = { uid: url.searchParams.get('uid'), ctr: url.searchParams.get('ctr'), cmac: url.searchParams.get('cmac') };
  console.log(`     URL lue : ${url.href}`);
  if (got.uid !== uid) throw new StepFailure(step, `UID dans l'URL (${got.uid}) ≠ UID réel (${uid})`);
  const expected = sdm.sdmMac(k1, got.uid, got.ctr);
  if (got.cmac !== expected) throw new StepFailure(step, `CMAC ${got.cmac} ≠ attendu ${expected} (avec K1)`);
  console.log(`     CMAC ${got.cmac} ✔ vérifié avec K1 (compteur ${got.ctr})`);
  return url.href;
}

const keysPath = uid => path.join(__dirname, `keys-${uid}.json`);

function saveKeys(uid, k0, k1, status) {
  const file = keysPath(uid);
  const content = JSON.stringify({ uid, k0, k1_sun_secret: k1, date: new Date().toISOString(), status }, null, 2) + '\n';
  fs.writeFileSync(file, content, { mode: 0o600, flag: status === 'en cours' ? 'wx' : 'w' });
  return file;
}

// Ajoute / remplace des champs du fichier de clés sans toucher aux clés ni au statut.
function updateKeysFile(uid, patch) {
  const file = keysPath(uid);
  const keys = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, JSON.stringify({ ...keys, ...patch }, null, 2) + '\n', { mode: 0o600 });
}

// Rappel avant le point de non-retour. Les clés elles-mêmes ne sont jamais affichées.
function printKeys(uid, file) {
  console.log('\n   ╔════════════════════════════════════════════════════════════╗');
  console.log('   ║  🔑 CLÉS SAUVEGARDÉES — garde ce fichier en lieu sûr          ║');
  console.log('   ╚════════════════════════════════════════════════════════════╝');
  console.log(`     UID            : ${uid}`);
  console.log(`     K0, K1         : ${HIDDEN}`);
  console.log(`     Fichier        : ${file}\n`);
}

// --- Administration : session, choix de l'item, liaison --------------------------------

async function adminLogin() {
  const cfg = api.loadAdminConfig();
  console.log('🔐 Connexion admin (Supabase)');
  const email = await ask('   Email        : ');
  const password = await askHidden('   Mot de passe : ');
  if (!email || !password) throw new Error('email et mot de passe requis');
  const client = api.createAdminClient(cfg);
  const who = await api.login(client, email, password);
  console.log(`   ✔ connecté : ${who}\n`);
  return { client, cfg };
}

async function chooseItem(client) {
  for (;;) {
    const q = await ask('🔎 Nom de l\'item (une partie suffit) : ');
    if (!q) continue;
    const items = await api.searchItems(client, q);
    if (!items.length) {
      console.log('   Aucun item trouvé.\n');
      continue;
    }
    items.forEach((it, i) => console.log(`   ${String(i + 1).padStart(2)}. #${it.id}  ${it.name}  (${it.status ?? '—'})`));
    const pick = await ask('   Numéro de l\'item (Entrée = nouvelle recherche) : ');
    const n = Number(pick);
    if (Number.isInteger(n) && n >= 1 && n <= items.length) {
      console.log(`   ✔ ${items[n - 1].name} (#${items[n - 1].id})\n`);
      return items[n - 1];
    }
  }
}

async function chooseJob(client) {
  const item = await chooseItem(client);
  let size = '';
  while (!/^[A-Z0-9]{1,6}$/.test(size)) size = (await ask('📏 Taille (S, M, L, XL…) : ')).toUpperCase();
  const color = (await ask('🎨 Couleur (optionnel, Entrée pour ignorer) : ')) || null;
  console.log(`\n   ➜ Puces à lier à : ${item.name} (#${item.id}), taille ${size}${color ? `, ${color}` : ''}\n`);
  return { item, size, color };
}

// Lie une puce programmée à un exemplaire. Ne lève jamais : un échec n'annule pas la programmation.
async function linkProgrammedChip(admin, job, uid, k1) {
  console.log(`\n🔗 Liaison : POST ${admin.cfg.backendUrl}/api/admin/link-chip`);
  console.log(`   ${JSON.stringify({ uid, sun_secret: '«masqué»', item_id: job.item.id, size: job.size, ...(job.color ? { color: job.color } : {}) })}`);
  let r;
  try {
    const token = await api.accessToken(admin.client);
    r = await api.linkChip({
      backendUrl: admin.cfg.backendUrl, token,
      uid, sunSecret: k1, itemId: job.item.id, size: job.size, color: job.color,
    });
  } catch (e) {
    r = { ok: false, status: null, body: e.name === 'TimeoutError' ? 'délai dépassé (backend injoignable ?)' : e.message };
  }
  const shown = api.redact(r.body);
  console.log(`   ← ${r.status ? `HTTP ${r.status}` : 'pas de réponse'} : ${typeof shown === 'string' ? shown.slice(0, 500) : JSON.stringify(shown)}`);

  const ex = api.exemplaireFrom(r.body);
  updateKeysFile(uid, {
    link: r.ok
      ? { ok: true, item_id: job.item.id, item_name: job.item.name, serial_number: ex.serialNumber,
          size: ex.size ?? job.size, color: ex.color ?? job.color, date: new Date().toISOString() }
      : { ok: false, item_id: job.item.id, size: job.size, color: job.color, http_status: r.status,
          error: typeof shown === 'string' ? shown.slice(0, 300) : shown, date: new Date().toISOString() },
  });

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  if (r.ok) {
    console.log(`✅ PUCE PROGRAMMÉE ET LIÉE — ${job.item.name} exemplaire n°${ex.serialNumber ?? '?'}, `
      + `taille ${ex.size ?? job.size}${(ex.color ?? job.color) ? `, ${ex.color ?? job.color}` : ''}`);
    console.log(`   UID ${uid}`);
  } else {
    console.log('⚠️  PUCE PROGRAMMÉE MAIS PAS LIÉE');
    console.log(`   La puce ${uid} EST programmée et vérifiée (clés dans ${path.basename(keysPath(uid))}).`);
    console.log('   Elle n\'est rattachée à aucun exemplaire. Ne la reprogramme pas : relance seulement la liaison :');
    console.log(`     node program.js --link-only ${uid}`);
    process.exitCode = 1;
  }
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  return r.ok;
}

// Liaison seule, sans lecteur, pour une puce déjà programmée et vérifiée.
async function linkOnly(uid) {
  if (!/^[0-9A-F]{14}$/.test(uid)) throw new Error('usage : node program.js --link-only <UID sur 14 caractères hex>');
  const file = keysPath(uid);
  if (!fs.existsSync(file)) throw new Error(`${path.basename(file)} introuvable`);
  const keys = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (keys.uid !== uid || !/^[0-9A-F]{32}$/i.test(keys.k1_sun_secret || '')) throw new Error(`${path.basename(file)} invalide`);
  if (keys.status !== 'programmée et vérifiée') {
    throw new Error(`${path.basename(file)} : statut « ${keys.status} » — seule une puce programmée et vérifiée peut être liée`);
  }
  if (keys.link?.ok) {
    throw new Error(`puce déjà liée : ${keys.link.item_name} exemplaire n°${keys.link.serial_number} (${keys.link.date})`);
  }
  console.log(`🔗 Liaison seule de la puce ${uid} (aucun lecteur, aucune programmation)\n`);
  const admin = await adminLogin();
  try {
    const job = await chooseJob(admin.client);
    const ok = await ask(`Lier la puce ${uid} à ${job.item.name}, taille ${job.size} ? Tape OUI : `);
    if (ok !== 'OUI') return console.log('⏹  Annulé.');
    await linkProgrammedChip(admin, job, uid, keys.k1_sun_secret.toUpperCase());
  } finally {
    await admin.client.auth.signOut().catch(() => {});
  }
}

// --- Déroulé principal ---------------------------------------------------------------
async function run(reader, isCardPresent) {
  const send = makeLink(reader);
  const k0 = loadK0();
  const cfg = sdm.ntvSdmConfig();
  let step = 'Lecture UID';
  let keysFile = null;
  let k1 = null;
  let uid = null;
  let k0Sent = false;

  try {
    // 0) Personne d'autre ne doit pouvoir parler à la carte pendant la session.
    step = 'Connexion exclusive au lecteur';
    await lockReaderExclusive(reader);

    // 1) UID (seule commande rejouée en cas d'erreur de transmission)
    step = 'Lecture UID';
    const u = await readUidWithRetry(send, isCardPresent);
    expect(step, u.sw, '9000');
    uid = u.data;
    if (!/^[0-9A-F]{14}$/.test(uid)) throw new StepFailure(step, `UID de 7 octets attendu, reçu ${uid}`);
    console.log(`\n💳 UID : ${uid}\n`);
    // Ne jamais reprogrammer une puce qui a déjà un fichier de clés.
    if (EXECUTE && fs.existsSync(keysPath(uid))) {
      let hint = 'déplace-le seulement si tu es sûr que cette puce n\'a jamais été programmée';
      try {
        const k = JSON.parse(fs.readFileSync(keysPath(uid), 'utf8'));
        if (k.status === 'programmée et vérifiée') {
          hint = k.link?.ok
            ? `puce déjà programmée ET liée (${k.link.item_name} n°${k.link.serial_number})`
            : `puce déjà programmée mais PAS liée → node program.js --link-only ${uid}`;
        }
      } catch { /* fichier illisible : message générique */ }
      throw new StepFailure(step, `keys-${uid}.json existe déjà : ${hint}`);
    }

    // 2) SELECT
    step = 'SELECT application NDEF';
    expect(step, split(await send(step, '00A4040007D276000085010100')).sw, '9000');

    // 3) Clé 1 usine ? (nécessaire : ChangeKey clé 1 utilise l'ancienne clé)
    step = 'Contrôle clé 1 usine';
    await authenticate(send, '01', ZERO_KEY, 'clé 1 (usine, contrôle)');
    console.log('     ✔ clé 1 = clé usine\n');

    // 4) Session avec la clé 0 usine
    step = 'Authentification clé 0 usine';
    const session = await authenticate(send, '00', ZERO_KEY, 'clé 0 (usine)');
    console.log(`     ✔ session ouverte (TI ${session.ti})\n`);

    // 5) État du fichier NDEF
    step = 'GetFileSettings';
    const settings = await smExchange(send, session, 'GetFileSettings fichier NDEF (02)',
      sm.buildCommand(session, 'F5', '02', '', 'mac'), 'mac');
    checkFactoryFileSettings(settings, cfg.length);
    console.log('     ✔ puce vierge (réglages usine)\n');

    // 6) Plan
    step = 'Calcul du plan';
    k1 = crypto.randomBytes(16).toString('hex').toUpperCase();
    const plan = prog.programmingPlan({ k0, k1, sdm: cfg, chunkSize: CHUNK_SIZE });
    const preview = { ...session };
    console.log('━━━━━━━━━━━━━━━━ PLAN DE PROGRAMMATION ━━━━━━━━━━━━━━━━');
    console.log(`   UID              : ${uid}`);
    console.log(`   URL (modèle)     : ${cfg.url}`);
    console.log(`   Offsets          : UID ${cfg.offsets.uidOffset}, compteur ${cfg.offsets.sdmReadCtrOffset}, CMAC ${cfg.offsets.sdmMacOffset}`);
    console.log(`   File settings    : ${cfg.fileSettingsHex}`);
    console.log(`   K0 (.env)        : ${HIDDEN}`);
    console.log(`   K1 (sun_secret)  : générée aléatoirement, ${EXECUTE ? HIDDEN : 'jetable (dry-run)'}`);
    plan.forEach((s, i) => {
      console.log(`\n   ${i + 1}. ${s.name}  [CmdCtr ${preview.cmdCtr}]`);
      console.log(`      ${s.build(preview)}`);
      preview.cmdCtr += 1;
    });
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    if (!EXECUTE) {
      console.log('🟡 DRY-RUN terminé : AUCUNE écriture effectuée.');
      console.log('   Pour programmer réellement : node program.js --execute');
      return { ok: false, dryRun: true };
    }

    // 7) Confirmation
    step = 'Confirmation';
    const answer = await ask(`⚠️  Programmer DÉFINITIVEMENT la puce ${uid} ? Tape OUI pour continuer : `);
    if (answer !== 'OUI') {
      console.log('\n⏹  Annulé : aucune écriture effectuée.');
      return { ok: false, cancelled: true };
    }
    if (!isCardPresent()) throw new StepFailure(step, 'puce retirée pendant la confirmation — rien n\'a été écrit');

    // 8) Sauvegarde des clés AVANT toute écriture (K1 devient irrécupérable dès l'étape 3)
    step = 'Sauvegarde des clés';
    keysFile = saveKeys(uid, k0, k1, 'en cours');
    console.log(`\n💾 Clés sauvegardées : ${keysFile}\n`);

    // 9) Envoi des 4 commandes, dans l'ordre
    for (const [i, s] of plan.entries()) {
      step = `${i + 1}/${plan.length} ${s.name}`;
      if (i === plan.length - 1) {
        printKeys(uid, keysFile);
        console.log('   ⛔ Point de non-retour : changement de K0.\n');
      }
      await smExchange(send, session, step, s.build(session), s.responseMode);
      if (i === plan.length - 1) k0Sent = true;
      console.log('     ✔\n');
    }
    saveKeys(uid, k0, k1, 'programmée — vérification en cours');

    // 10) Vérifications (lecture seule)
    step = 'Vérification SUN';
    const url = await verifySun(send, uid, k1, cfg);
    step = 'Vérification K0';
    await authenticate(send, '00', k0, 'clé 0 (nouvelle K0)');
    console.log('     ✔ la puce accepte la nouvelle K0\n');
    saveKeys(uid, k0, k1, 'programmée et vérifiée');

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✅ PUCE PROGRAMMÉE ET VÉRIFIÉE');
    console.log(`   UID            : ${uid}`);
    console.log(`   K1 (sun_secret): ${HIDDEN}`);
    console.log(`   URL            : ${api.redact(url)}`);
    console.log(`   Clés           : ${keysFile}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    return { ok: true, uid, k1 };
  } catch (err) {
    const where = err instanceof StepFailure ? err.step : step;
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`❌ ÉCHEC à l'étape « ${where} »`);
    console.log(`   ${err.message}`);
    if (keysFile) {
      console.log(`   Clés de cette tentative : ${keysFile}`);
      console.log(k0Sent
        ? '   K0 a été changée : la puce se ré-authentifie avec la NOUVELLE K0.'
        : '   K0 n\'a PAS été changée : la puce reste accessible avec la clé 0 usine.');
      try {
        saveKeys(uid, k0, k1, `échec : ${where} — ${err.message}`);
      } catch (e) {
        console.log(`   ⚠️ Mise à jour du fichier de clés impossible : ${e.message}`);
      }
    } else {
      console.log('   Aucune écriture n\'a été effectuée.');
    }
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    process.exitCode = 1;
    return { ok: false };
  }
}

// --- Lecteur et enchaînement des puces -------------------------------------------------

async function main() {
  loadEnv(); // pour tous les modes, y compris --link-only (SUPABASE_*, BACKEND_URL)
  if (LINK_ONLY_UID !== null) {
    await linkOnly(LINK_ONLY_UID);
    return process.exit();
  }

  console.log(EXECUTE
    ? '🔴 MODE EXECUTE — chaque puce est programmée après confirmation (OUI), puis liée à un exemplaire'
    : '🟢 MODE DRY-RUN — lecture seule, aucune écriture possible');
  console.log(`   APDU autorisées : ${Object.values(ALLOWED).join(', ')}\n`);

  loadK0();
  if (EXECUTE && !process.stdin.isTTY) throw new Error('--execute exige un terminal interactif (confirmation OUI).');

  // Session admin et exemplaire cible : une seule fois, AVANT de toucher une puce.
  let admin = null;
  let job = null;
  if (EXECUTE) {
    admin = await adminLogin();
    job = await chooseJob(admin.client);
  }

  const finish = async () => {
    if (admin) await admin.client.auth.signOut().catch(() => {});
    process.exit();
  };

  const nfc = new NFC();
  let busy = false;
  let cardGen = 0; // incrémenté à chaque pose de puce

  nfc.on('reader', reader => {
    reader.autoProcessing = false;
    let present = false;
    console.log(`✅ Lecteur : ${reader.reader.name}`);
    console.log('👉 Pose UNE puce vierge et laisse-la en place jusqu\'à la fin...\n');

    const handleCard = async () => {
      busy = true;
      const gen = cardGen;
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      await sleep(CARD_SETTLE_MS); // laisse le lecteur finir l'activation de la carte
      const result = await run(reader, () => present);

      // La liaison n'a lieu qu'après une programmation ENTIÈREMENT réussie (CMAC et K0 vérifiés).
      if (result.ok) await linkProgrammedChip(admin, job, result.uid, result.k1);

      if (!EXECUTE) return finish(); // dry-run : une seule puce

      const next = (await ask('\n➕ Autre puce ? [Entrée] même item/taille · [n] nouvel item · [q] quitter : ')).toLowerCase();
      if (next === 'q') return finish();
      if (next === 'n') job = await chooseJob(admin.client);
      console.log(`👉 Retire la puce ${result.uid || ''} et pose la suivante (${job.item.name}, ${job.size})...\n`);
      busy = false;
      // Une nouvelle puce posée pendant les questions : on la traite tout de suite.
      if (present && cardGen !== gen) handleCard();
    };

    reader.on('card', () => {
      present = true;
      cardGen += 1;
      if (!busy) handleCard();
    });
    reader.on('card.off', () => {
      present = false;
      console.log('   (puce retirée)');
    });
    reader.on('error', err => console.error(`⚠️ Erreur lecteur : ${err.message}`));
  });

  nfc.on('error', err => console.error(`⚠️ Erreur NFC : ${err.message}`));
}

main().catch(err => {
  console.error(`\n❌ ${err.message}`);
  process.exit(1);
});
