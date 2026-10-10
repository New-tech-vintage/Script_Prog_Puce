const { NFC } = require('nfc-pcsc');

// autoProcessing: false → on parle nous-mêmes à la puce, pas de lecture auto
const nfc = new NFC();

console.log('🔍 En attente du lecteur... (Ctrl+C pour quitter)\n');

nfc.on('reader', reader => {
  reader.autoProcessing = false;  // désactive la lecture auto qui plante sur NTAG 424
  console.log(`✅ Lecteur détecté : ${reader.reader.name}\n`);
  console.log('👉 Pose une puce sur le lecteur...\n');

  reader.on('card', async card => {
    const atr = card.atr ? card.atr.toString('hex').toUpperCase() : '(aucun)';
    try {
      // Commande ACR122U pour lire l'UID : FF CA 00 00 00
      const resp = await reader.transmit(Buffer.from([0xFF, 0xCA, 0x00, 0x00, 0x00]), 12);
      const sw = resp.slice(-2).toString('hex').toUpperCase();      // status (9000 = OK)
      const uid = resp.slice(0, -2).toString('hex').toUpperCase();  // l'UID
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`💳 PUCE DÉTECTÉE`);
      console.log(`   UID    : ${uid}`);
      console.log(`   Status : ${sw}  ${sw === '9000' ? '(OK)' : '(erreur)'}`);
      console.log(`   ATR    : ${atr}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    } catch (err) {
      console.error(`⚠️ Erreur lecture UID : ${err.message}\n`);
    }
  });

  reader.on('card.off', () => console.log('   (puce retirée)\n'));
  reader.on('error', err => console.error(`⚠️ Erreur lecteur : ${err.message}`));
});

nfc.on('error', err => console.error(`⚠️ Erreur NFC : ${err.message}`));
