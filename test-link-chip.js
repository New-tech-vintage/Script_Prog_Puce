const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { createClient } = require('@supabase/supabase-js');

// Test de la route backend POST /api/admin/link-chip avec la puce B déjà programmée.
// Aucun lecteur NFC : uniquement un appel HTTP authentifié (session admin Supabase).
// Le sun_secret (K1) est lu dans keys-<UID>.json et n'est JAMAIS affiché.

const UID = '0456898A2B1D90';
const ITEM_ID = 50;
const SIZE = 'S';

// --- Configuration ---------------------------------------------------------------
function loadConfig() {
  process.loadEnvFile(path.join(__dirname, '.env'));
  const cfg = {
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY,
    backendUrl: (process.env.BACKEND_URL || '').replace(/\/+$/, ''),
  };
  for (const [name, value] of Object.entries({
    SUPABASE_URL: cfg.supabaseUrl, SUPABASE_ANON_KEY: cfg.supabaseAnonKey, BACKEND_URL: cfg.backendUrl,
  })) {
    if (!value) throw new Error(`${name} absente du .env`);
  }
  // Le sun_secret part dans le corps de la requête : uniquement sur une connexion chiffrée.
  if (!cfg.backendUrl.startsWith('https://')) throw new Error('BACKEND_URL doit commencer par https://');
  return cfg;
}

function loadSunSecret(uid) {
  const file = path.join(__dirname, `keys-${uid}.json`);
  const keys = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (keys.uid !== uid) throw new Error(`${path.basename(file)} : UID ${keys.uid} ≠ ${uid}`);
  if (!/^[0-9A-F]{32}$/i.test(keys.k1_sun_secret || '')) throw new Error(`${path.basename(file)} : k1_sun_secret invalide`);
  if (keys.status !== 'programmée et vérifiée') {
    throw new Error(`${path.basename(file)} : statut « ${keys.status} » — la puce n'est pas marquée comme programmée et vérifiée`);
  }
  return keys.k1_sun_secret.toUpperCase();
}

// --- Saisie console ----------------------------------------------------------------
function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, a => { rl.close(); resolve(a.trim()); }));
}

// Saisie masquée : les caractères tapés ne sont pas affichés.
function askHidden(question) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) return reject(new Error('saisie du mot de passe : terminal interactif requis'));
    process.stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const done = (err) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stdout.write('\n');
      err ? reject(err) : resolve(value);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') return done();
        if (ch === '\u0003') return done(new Error('saisie annulée (Ctrl+C)'));
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

// Affichage d'une réponse sans jamais révéler de secret.
function redact(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) =>
    /secret|token|password|key/i.test(k) && typeof v === 'string' ? '«masqué»' : v));
}

// --- Main ----------------------------------------------------------------------------
async function main() {
  const cfg = loadConfig();
  const sunSecret = loadSunSecret(UID);
  const endpoint = `${cfg.backendUrl}/api/admin/link-chip`;

  console.log('🔗 Test POST /api/admin/link-chip — aucun lecteur, aucune programmation');
  console.log(`   Backend   : ${endpoint}`);
  console.log(`   UID       : ${UID}`);
  console.log(`   item_id   : ${ITEM_ID}   size : ${SIZE}`);
  console.log(`   sun_secret: lu depuis keys-${UID}.json (masqué)\n`);

  const email = await ask('Email admin : ');
  const password = await askHidden('Mot de passe : ');
  if (!email || !password) throw new Error('email et mot de passe requis');

  const supabase = createClient(cfg.supabaseUrl, cfg.supabaseAnonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  console.log('\n🔐 Connexion Supabase...');
  const { data: auth, error: authError } = await supabase.auth.signInWithPassword({ email, password });
  if (authError || !auth?.session?.access_token) {
    throw new Error(`connexion Supabase refusée : ${authError?.message || 'pas de session'}`);
  }
  console.log(`   ✔ connecté : ${auth.user.email}\n`);

  try {
    console.log(`📤 POST ${endpoint}`);
    console.log(`   body : ${JSON.stringify({ uid: UID, sun_secret: '«masqué»', item_id: ITEM_ID, size: SIZE })}`);
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auth.session.access_token}`,
      },
      body: JSON.stringify({ uid: UID, sun_secret: sunSecret, item_id: ITEM_ID, size: SIZE }),
    });

    const text = await res.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }

    console.log(`\n📥 HTTP ${res.status} ${res.statusText}`);
    const shown = typeof body === 'object' && body !== null ? redact(body) : body;
    console.log(typeof shown === 'string' ? `   ${shown.slice(0, 2000)}` : JSON.stringify(shown, null, 2));

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    if (res.ok) {
      const ex = body?.exemplaire || body;
      console.log('✅ PUCE LIÉE');
      console.log(`   serial_number : ${ex?.serial_number ?? '(absent)'}`);
      console.log(`   size          : ${ex?.size ?? '(absent)'}`);
      console.log(`   color         : ${ex?.color ?? '(absent)'}`);
    } else {
      console.log(`❌ ÉCHEC (HTTP ${res.status})`);
      process.exitCode = 1;
    }
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  } finally {
    await supabase.auth.signOut().catch(() => {});
  }
}

main().catch(err => {
  console.error(`\n❌ ${err.message}`);
  process.exitCode = 1;
});
