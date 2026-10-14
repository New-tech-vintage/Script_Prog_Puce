# Script_Prog_Puce

Outil de programmation des puces **NTAG 424 DNA** pour NTV, via un lecteur **ACR122U** (Node.js + [`nfc-pcsc`](https://github.com/pokusew/nfc-pcsc)).
Objectif final : configurer le mode SUN/SDM (URL authentifiée générée par la puce à chaque lecture).

## Installation

```bash
npm install
npm test
```

## Scripts

| Script | Rôle | Écrit sur la puce ? |
|---|---|---|
| `read-uid.js` | Lit l'UID de la puce posée | Non |
| `check-state.js` | Diagnostic : SELECT NDEF + début d'authentification pour savoir si la clé usine est en place | Non |
| `auth-test.js` | AuthenticateEV2First complète (clé 0) : affiche TI et clés de session | Non |
| `sm-test.js` | Authentification + `GetCardUID` en Secure Messaging chiffré, comparé à l'UID en clair | Non (liste blanche d'APDU) |
| `write-test.js` | Diagnostic de la taille max d'APDU (écriture/lecture du NDEF par tailles croissantes, puce vierge uniquement) | Oui, fichier NDEF seulement (ni clés ni paramètres) |
| `program.js` | Programmation SUN/SDM puis liaison à un exemplaire. Dry-run par défaut (aucune écriture, aucune connexion admin). `--execute` : connexion admin Supabase (une fois), choix item/taille/couleur, puis pour chaque puce plan + `OUI`, programmation, vérification CMAC, `POST /api/admin/link-chip` ; enchaîne plusieurs puces. `--link-only <UID>` : lie une puce déjà programmée sans lecteur. Lecteur en mode exclusif, URL écrite par fragments (`--chunk=N`). Clés dans `keys-<UID>.json` (ignoré par git), jamais affichées | Oui, seulement avec `--execute` |
| `chip-cli.js` | Outil de programmation complet (Supabase / backend NTV) | Oui |

Lancement : `node <script>`, puis poser une puce sur le lecteur.

## Bibliothèque

- `lib/auth-crypto.js` — crypto d'AuthenticateEV2First (AES-128, RndA/RndB, SV1/SV2, AES-CMAC).
- `lib/secure-messaging.js` — Secure Messaging EV2 : IV de session, chiffrement CommMode.FULL, MAC tronqué, CmdCtr, assemblage/analyse des APDU.
- `lib/sdm-config.js` — fichier NDEF (URL avec champs miroir), offsets SDM, paramètres ChangeFileSettings, calcul du CMAC SUN.
- `lib/programmer.js` — commandes de programmation (WriteData, ChangeFileSettings, ChangeKey) et ordre d'envoi.
- `lib/admin-api.js` — session admin Supabase, recherche d'items, appel `POST /api/admin/link-chip`, masquage des secrets.
- `lib/prompt.js` — saisies console (mot de passe masqué).

Fonctions pures (hexadécimal en entrée/sortie, aucun accès NFC).

## Validation

La crypto est testée (`npm test`, 109 tests) contre les vecteurs officiels de
**NXP AN12196 Rev. 2.0 — « NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints »** (4 mars 2025),
§4.3, §5.6, §5.8–§5.16, §6.2–§6.3, ainsi que contre la RFC 4493 pour l'AES-CMAC.
Le document n'est pas inclus dans ce dépôt (copyright NXP) ; il est disponible sur nxp.com.

L'authentification et le Secure Messaging ont aussi été validés sur une vraie puce.

## Sécurité

Les clés réelles ne sont **jamais** commitées. Les seules clés présentes dans le code sont la clé usine
(16 octets à zéro) et les vecteurs de test publiés par NXP. Les identifiants Supabase sont lus depuis
les variables d'environnement (`.env`, exclu par `.gitignore`), tout comme les exports `chip-*.txt` et les fichiers de clés `keys-*` (y compris les archives `keys-*.echecN`).
