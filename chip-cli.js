const { NFC } = require('nfc-pcsc');
const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// Configuration
const BACKEND_URL = 'https://backend-contracts-ntv.onrender.com';
const BASE_URL = 'https://backend-contracts-ntv.onrender.com/api/nfc/verify';

// Client Supabase avec service_role
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const nfc = new NFC();
let currentReader = null;
let currentUID = null;
let currentAESKey = null;
let currentItemID = null;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: 'NFC-CLI> '
});

// ============================================
// FONCTIONS SUPABASE
// ============================================

async function saveToSupabase(uid, sunSecret, itemId) {
  try {
    const { data, error } = await supabase
      .from('nfc_chips')
      .upsert({
        uid: uid,
        sun_secret: sunSecret,
        item_id: itemId,
        status: 'programmed',
        programmed_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }, {
        onConflict: 'uid',
        ignoreDuplicates: false
      })
      .select()
      .single();
    
    if (error) {
      console.error('Erreur Supabase:', error);
      return { success: false, error: error.message };
    }
    
    return { success: true, data };
    
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function checkChipExists(uid) {
  try {
    const { data, error } = await supabase
      .from('nfc_chips')
      .select(`
        *,
        items (
          id,
          name,
          description
        )
      `)
      .eq('uid', uid)
      .single();
    
    if (error && error.code === 'PGRST116') {
      // Puce non trouvée
      return { exists: false };
    }
    
    if (error) {
      console.error('Erreur Supabase:', error);
      return { exists: false, error: error.message };
    }
    
    return { exists: true, chip: data };
    
  } catch (error) {
    return { exists: false, error: error.message };
  }
}

// ============================================
// COMMANDES CLI
// ============================================

const commands = {
  help: () => {
    console.log('\n  COMMANDES DISPONIBLES :');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  help              - Afficher cette aide');
    console.log('  load              - Charger données depuis Supabase');
    console.log('  check             - Vérifier si la puce existe déjà');
    console.log('  generate          - Générer une clé AES');
    console.log('  set-item <id>     - Définir l\'ID de l\'item');
    console.log('  show              - Afficher les infos actuelles');
    console.log('  url               - Générer et afficher l\'URL NFC');
    console.log('  save              - Enregistrer dans Supabase');
    console.log('  activate-sun      - Activer le mode SUN (APDU)');
    console.log('  export            - Exporter dans un fichier texte');
    console.log('  nfc-tools         - Afficher les instructions NFC Tools');
    console.log('  reset             - Réinitialiser les données');
    console.log('  exit              - Quitter');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('   L\'UID est détecté automatiquement\n');
    console.log('   WORKFLOW PUCE VIERGE :\n');
    console.log('   1. Pose puce → UID détecté');
    console.log('   2. set-item 32');
    console.log('   3. generate');
    console.log('   4. save');
    console.log('   5. activate-sun\n');
    console.log('   WORKFLOW PUCE DÉJÀ PROGRAMMÉE :\n');
    console.log('   1. Pose puce → UID détecté');
    console.log('   2. load (charge depuis Supabase)');
    console.log('   3. activate-sun\n');
  },

  load: async () => {
    if (!currentUID) {
      console.log(' Aucun UID détecté. Pose une puce sur le lecteur\n');
      return;
    }

    console.log(` Chargement des données pour ${currentUID}...\n`);
    const check = await checkChipExists(currentUID);
    
    if (!check.exists) {
      console.log(' Puce non trouvée dans Supabase\n');
      return;
    }

    // Charger les données depuis Supabase
    currentAESKey = check.chip.sun_secret;
    currentItemID = check.chip.item_id;
    
    console.log(' Données chargées depuis Supabase :');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`   UID         : ${check.chip.uid}`);
    console.log(`   Clé AES     : ${currentAESKey}`);
    console.log(`   Item ID     : ${currentItemID}`);
    console.log(`   Status      : ${check.chip.status}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log(' Maintenant tu peux utiliser "activate-sun"\n');
  },

  check: async () => {
    if (!currentUID) {
      console.log(' Aucun UID détecté. Pose une puce sur le lecteur\n');
      return;
    }

    console.log(` Vérification de l'UID ${currentUID}...\n`);
    const check = await checkChipExists(currentUID);
    
    if (check.exists) {
      console.log(' PUCE TROUVÉE DANS LA BASE :');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`   UID         : ${check.chip.uid}`);
      console.log(`   Status      : ${check.chip.status}`);
      console.log(`   Item        : ${check.chip.items?.name || 'Non associé'}`);
      console.log(`   Programmée  : ${new Date(check.chip.programmed_at).toLocaleString('fr-FR')}`);
      console.log(`   Scans       : ${check.chip.scan_count || 0}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    } else {
      console.log(' Puce vierge - Pas encore enregistrée dans la base\n');
    }
  },

  generate: () => {
    currentAESKey = crypto.randomBytes(16).toString('hex').toUpperCase();
    console.log(` Clé AES générée : ${currentAESKey}\n`);
  },

  'set-item': (args) => {
    const itemId = parseInt(args[0]);
    if (isNaN(itemId)) {
      console.log(' ID invalide. Usage: set-item <id>\n');
      return;
    }
    currentItemID = itemId;
    console.log(` Item ID défini : ${currentItemID}\n`);
  },

  show: () => {
    console.log('\n DONNÉES ACTUELLES :');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  UID         : ${currentUID || '❌ Non détecté'}`);
    console.log(`  Clé AES     : ${currentAESKey || '❌ Non générée/chargée'}`);
    console.log(`  Item ID     : ${currentItemID || '❌ Non défini'}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  },

  url: () => {
    if (!currentUID) {
      console.log(' Aucun UID détecté\n');
      return;
    }
    const url = `${BASE_URL}?uid=${currentUID}&ctr=00000001&cmac=TEST123`;
    console.log('\n URL GÉNÉRÉE :');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(url);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  },

  save: async () => {
    if (!currentUID || !currentAESKey || !currentItemID) {
      console.log(' Données incomplètes. Vérifie avec "show"\n');
      return;
    }

    console.log(' Vérification finale...');
    const check = await checkChipExists(currentUID);
    
    if (check.exists && check.chip.status !== 'virgin') {
      console.log('  Cette puce est déjà enregistrée.');
      console.log(' Utilise "load" pour charger ses données\n');
      return;
    }

    console.log(' Envoi à Supabase...');
    const result = await saveToSupabase(currentUID, currentAESKey, currentItemID);
    
    if (result.success) {
      console.log(' Données enregistrées dans Supabase\n');
      console.log(' Prochaines étapes:\n');
      console.log('   - activate-sun (tenter activation mode SUN)\n');
      console.log('   - export (sauvegarder localement)\n');
    } else {
      console.log(` Erreur: ${result.error}\n`);
    }
  },

  'activate-sun': async () => {
    if (!currentReader) {
      console.log(' Aucun lecteur NFC connecté\n');
      return;
    }
    
    if (!currentUID || !currentAESKey) {
      console.log(' Données manquantes. Assure-toi d\'avoir:\n');
      console.log('   - UID détecté (pose la puce)');
      console.log('   - Clé AES (commande: load ou generate)\n');
      return;
    }
    
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║              ACTIVATION MODE SUN - NTAG424 DNA              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log(` UID: ${currentUID}`);
    console.log(` Clé AES: ${currentAESKey}\n`);
    
    try {
      // ÉTAPE 1: SELECT APPLICATION
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('ÉTAPE 1: SELECT APPLICATION');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      
      const selectApp = Buffer.from('00A4040007D2760000850101', 'hex');
      const selectResp = await currentReader.transmit(selectApp, 255);
      const selectStatus = selectResp.slice(-2);
      
      console.log(` Commande: ${selectApp.toString('hex').toUpperCase()}`);
      console.log(` Réponse: ${selectResp.toString('hex').toUpperCase()}\n`);
      
      if (selectStatus[0] !== 0x90 || selectStatus[1] !== 0x00) {
        console.log(' Échec SELECT APPLICATION\n');
        return;
      }
      
      console.log(' Application sélectionnée\n');
      
      // ÉTAPE 2: AUTHENTICATE
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('ÉTAPE 2: AUTHENTICATE (clé par défaut)');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      
      const authCmd = Buffer.from('9000010000', 'hex');
      const authResp = await currentReader.transmit(authCmd, 255);
      const authStatus = authResp.slice(-2);
      
      console.log(` Commande: ${authCmd.toString('hex').toUpperCase()}`);
      console.log(` Réponse: ${authResp.toString('hex').toUpperCase()}\n`);
      
      if (authStatus[0] === 0x91 && authStatus[1] === 0xAF) {
        console.log(' Challenge reçu de la puce !\n');
        console.log('  Suite du protocole non implémentée\n');
        console.log('   (calculs crypto complexes nécessaires)\n');
      } else if (authStatus[0] === 0x91 && authStatus[1] === 0x1C) {
        console.log(' Erreur 911C: Permission denied\n');
      } else {
        console.log(`  Status: ${authStatus.toString('hex').toUpperCase()}\n`);
      }
      
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('RECOMMANDATION');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      
      console.log(' Utilise TagWriter by NXP pour finaliser :\n');
      console.log('   1. Télécharge "TagWriter by NXP" (gratuit)');
      console.log('   2. Advanced → NTAG424 DNA → Configure SDM');
      console.log(`   3. Clé K0: ${currentAESKey}`);
      console.log(`   4. URL: ${BASE_URL}?uid=[UID]&ctr=[CTR]&cmac=[CMAC]\n`);
      
    } catch (error) {
      console.error(`\n Erreur: ${error.message}\n`);
    }
  },

  export: () => {
    if (!currentUID) {
      console.log(' Aucune donnée à exporter\n');
      return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `chip-${currentUID}-${timestamp}.txt`;
    const url = `${BASE_URL}?uid=${currentUID}&ctr=[CTR]&cmac=[CMAC]`;
    
    const content = `
PUCE NTAG424 DNA - MODE SUN
═══════════════════════════════════════════════════════════

UID               : ${currentUID}
Clé AES-128       : ${currentAESKey || 'Non générée'}
Item ID           : ${currentItemID || 'Non défini'}
Date              : ${new Date().toLocaleString('fr-FR')}

URL SUN TEMPLATE  : ${url}

POUR NFC TAGWRITER BY NXP:
1. Télécharge "TagWriter by NXP" sur iPhone
2. Write tags → Advanced → NTAG424 DNA
3. Configure SDM:
   - Mode: SUN
   - Key 0: ${currentAESKey || '[CHARGER/GÉNÉRER D\'ABORD]'}
   - URL: ${url}
4. Write

═══════════════════════════════════════════════════════════
`;
    
    fs.writeFileSync(filename, content);
    console.log(` Exporté dans : ${filename}\n`);
  },

  'nfc-tools': () => {
    if (!currentUID) {
      console.log(' Aucun UID détecté\n');
      return;
    }

    console.log('\n INSTRUCTIONS NFC TAGWRITER BY NXP :');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('1. Télécharge "TagWriter by NXP" (gratuit)');
    console.log('2. Ouvre l\'app → Write tags');
    console.log('3. Advanced → NTAG424 DNA');
    console.log('4. Configure SDM:');
    console.log(`   - Key 0 (Hex): ${currentAESKey || '[CHARGER/GÉNÉRER D\'ABORD]'}`);
    console.log(`   - URL: ${BASE_URL}?uid=[UID]&ctr=[CTR]&cmac=[CMAC]`);
    console.log('5. Write → Scanne la puce\n');
    console.log(' La puce générera des URLs uniques à chaque scan !\n');
  },

  reset: () => {
    currentUID = null;
    currentAESKey = null;
    currentItemID = null;
    console.log(' Données réinitialisées\n');
  },

  exit: () => {
    console.log('\n Au revoir !\n');
    process.exit(0);
  }
};

// ============================================
// INITIALISATION NFC
// ============================================

nfc.on('reader', reader => {
  currentReader = reader;
  console.log(`\n Lecteur connecté: ${reader.reader.name}`);
  console.log(' En attente d\'une puce...\n');
  reader.autoProcessing = false;

  reader.on('card', async () => {
    console.log('\n PUCE DÉTECTÉE !');
    
    try {
      const getUID = Buffer.from([0xFF, 0xCA, 0x00, 0x00, 0x00]);
      const response = await currentReader.transmit(getUID, 255);
      const statusCode = response.slice(-2);
      
      if (statusCode[0] !== 0x90 || statusCode[1] !== 0x00) {
        console.log(` Erreur lecture UID\n`);
        rl.prompt();
        return;
      }
      
      const uidBytes = response.slice(0, -2);
      const newUID = uidBytes.toString('hex').toUpperCase();
      
      console.log(` UID : ${newUID}`);
      currentUID = newUID;
      
      console.log(' Vérification dans la base...');
      const check = await checkChipExists(newUID);
      
      if (check.exists && check.chip.status !== 'virgin') {
        console.log('\n  PUCE DÉJÀ PROGRAMMÉE !');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(`   UID         : ${check.chip.uid}`);
        console.log(`   Status      : ${check.chip.status}`);
        console.log(`   Item ID     : ${check.chip.items?.id || 'Non associé'}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
        console.log(' Utilise "load" pour charger les données\n');
      } else {
        console.log(' Puce vierge - Prête à être programmée\n');
      }
      
      rl.prompt();
    } catch (error) {
      console.error(`\n Erreur: ${error.message}\n`);
      rl.prompt();
    }
  });

  reader.on('error', err => {
    console.error(`\n Erreur lecteur: ${err.message}\n`);
    rl.prompt();
  });
});

nfc.on('error', err => {
  console.error(' Erreur NFC:', err);
});

// ============================================
// INTERFACE CLI
// ============================================

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║         PROGRAMMATION AUTOMATIQUE PUCES NTAG424              ║');
console.log('║                  AVEC MODE SUN INTÉGRÉ                       ║');
console.log('╚══════════════════════════════════════════════════════════════╝');
console.log('\n Pose une puce sur le lecteur pour démarrer');
console.log('   Tape "help" pour voir les commandes disponibles\n');

rl.prompt();

rl.on('line', async (line) => {
  const parts = line.trim().split(' ');
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1);

  if (commands[cmd]) {
    await commands[cmd](args);
  } else if (cmd) {
    console.log(` Commande inconnue: ${cmd}. Tape "help"\n`);
  }

  rl.prompt();
});

rl.on('close', () => {
  console.log('\n Au revoir !\n');
  process.exit(0);
});