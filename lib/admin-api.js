'use strict';

// Accès admin NTV : session Supabase (recherche d'items) et route backend POST /api/admin/link-chip.
// Aucun secret n'est jamais affiché : utiliser redact() pour toute réponse montrée à l'écran.

const { createClient } = require('@supabase/supabase-js');

// Render (offre gratuite) peut mettre près d'une minute à sortir de veille.
const LINK_TIMEOUT_MS = 60000;

function loadAdminConfig(env = process.env) {
  const cfg = {
    supabaseUrl: env.SUPABASE_URL,
    supabaseAnonKey: env.SUPABASE_ANON_KEY,
    backendUrl: (env.BACKEND_URL || '').replace(/\/+$/, ''),
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

// Session gardée en mémoire seulement ; le jeton est rafraîchi automatiquement pendant la session.
function createAdminClient(cfg) {
  return createClient(cfg.supabaseUrl, cfg.supabaseAnonKey, {
    auth: { persistSession: false, autoRefreshToken: true },
  });
}

async function login(client, email, password) {
  const { data, error } = await client.auth.signInWithPassword({ email, password });
  if (error || !data?.session?.access_token) {
    throw new Error(`connexion Supabase refusée : ${error?.message || 'pas de session'}`);
  }
  return data.user.email;
}

async function accessToken(client) {
  const { data, error } = await client.auth.getSession();
  const token = data?.session?.access_token;
  if (error || !token) throw new Error('session admin expirée : relance le script pour te reconnecter');
  return token;
}

// Échappe les jokers SQL LIKE (%, _ et \) pour chercher le texte tel quel.
function escapeLike(text) {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}

async function searchItems(client, query, limit = 20) {
  const { data, error } = await client
    .from('items')
    .select('id, name, status')
    .ilike('name', `%${escapeLike(query)}%`)
    .order('name')
    .limit(limit);
  if (error) throw new Error(`recherche d'items impossible : ${error.message}`);
  return data || [];
}

// Corps de la requête link-chip. La couleur est omise si elle n'est pas renseignée.
function linkChipBody({ uid, sunSecret, itemId, size, color }) {
  if (!/^[0-9A-F]{14}$/.test(uid)) throw new Error(`UID invalide : ${uid}`);
  if (!/^[0-9A-F]{32}$/.test(sunSecret)) throw new Error('sun_secret invalide');
  if (!Number.isInteger(itemId) || itemId <= 0) throw new Error(`item_id invalide : ${itemId}`);
  if (!size) throw new Error('taille manquante');
  const body = { uid, sun_secret: sunSecret, item_id: itemId, size };
  if (color) body.color = color;
  return body;
}

// POST /api/admin/link-chip. Ne lève pas d'exception pour une erreur HTTP : renvoie { ok, status, body }.
// Lève une exception pour une erreur réseau ou un délai dépassé.
async function linkChip({ backendUrl, token, fetchImpl = fetch, timeoutMs = LINK_TIMEOUT_MS, ...chip }) {
  const res = await fetchImpl(`${backendUrl}/api/admin/link-chip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(linkChipBody(chip)),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { ok: res.ok, status: res.status, body };
}

// La route renvoie l'exemplaire, directement ou sous la clé "exemplaire".
function exemplaireFrom(body) {
  const ex = body && typeof body === 'object' ? (body.exemplaire || body) : {};
  return { serialNumber: ex.serial_number ?? null, size: ex.size ?? null, color: ex.color ?? null };
}

// Copie affichable d'une réponse : tout champ secret / jeton / mot de passe / clé est masqué.
function redact(value) {
  if (typeof value === 'string') return value.replace(/\b[0-9A-Fa-f]{32}\b/g, '«masqué»');
  return JSON.parse(JSON.stringify(value, (k, v) => {
    if (/secret|token|password|key/i.test(k) && typeof v === 'string') return '«masqué»';
    return typeof v === 'string' ? v.replace(/\b[0-9A-Fa-f]{32}\b/g, '«masqué»') : v;
  }));
}

module.exports = {
  loadAdminConfig,
  createAdminClient,
  login,
  accessToken,
  escapeLike,
  searchItems,
  linkChipBody,
  linkChip,
  exemplaireFrom,
  redact,
};
