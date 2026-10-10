const { NFC } = require('nfc-pcsc');
const nfc = new NFC();

console.log('🔍 Diagnostic état des puces (LECTURE SEULE) — Ctrl+C pour quitter\n');

const hex = b => b.toString('hex').toUpperCase();

nfc.on('reader', reader => {
  reader.autoProcessing = false;
  console.log(`✅ Lecteur : ${reader.reader.name}`);
  console.log('👉 Pose une puce...\n');

  reader.on('card', async () => {
    try {
      // 1) UID
      const uidR = await reader.transmit(Buffer.from([0xFF,0xCA,0x00,0x00,0x00]), 12);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`UID : ${hex(uidR.slice(0,-2))}  (status ${hex(uidR.slice(-2))})`);

      // 2) SELECT application NDEF du NTAG 424 (lecture, conforme AN12196)
      const selApp = Buffer.from('00A4040007D276000085010100','hex');
      const selR = await reader.transmit(selApp, 255);
      console.log(`SELECT app NDEF : ${hex(selR.slice(-2))} ${hex(selR.slice(-2))==='9000'?'(OK)':''}`);

      // 3) AuthenticateEV2First avec clé 0 — ÉTAPE 1 SEULEMENT (on s'arrête au challenge)
      //    90 71 00 00 02 <KeyNo=00> <LenCap=00> 00
      const auth1 = Buffer.from('9071000002000000','hex');
      const authR = await reader.transmit(auth1, 255);
      const sw = hex(authR.slice(-2));
      console.log(`AUTH EV2 (clé 0, étape 1) : ${sw}`);

      if (sw === '91AF') {
        console.log('   → La puce a renvoyé un challenge.');
        console.log('   → La clé 0 par défaut (usine) est probablement ENCORE EN PLACE.');
        console.log('   → Puce très probablement VIERGE / reprogrammable. ✅');
      } else if (sw === '911C') {
        console.log('   → 911C (commande illégale ou refusée).');
        console.log('   → À creuser : format de commande ou puce dans un autre état.');
      } else if (sw.startsWith('91')) {
        console.log(`   → Erreur puce ${sw}. La clé par défaut ne démarre pas l\'auth.`);
        console.log('   → Puce peut-être DÉJÀ PROGRAMMÉE (clé custom). ⚠️');
      } else {
        console.log(`   → Réponse inattendue ${sw}.`);
      }

      console.log('   (aucune écriture effectuée — étape 1 seulement)');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    } catch (err) {
      console.error(`⚠️ Erreur : ${err.message}\n`);
    }
  });

  reader.on('card.off', () => console.log('   (puce retirée)\n'));
  reader.on('error', err => console.error(`⚠️ Erreur lecteur : ${err.message}`));
});

nfc.on('error', err => console.error(`⚠️ Erreur NFC : ${err.message}`));
