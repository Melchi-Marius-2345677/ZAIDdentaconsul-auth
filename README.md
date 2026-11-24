# DentaConsult — application de consultation bucco-dentaire

Application web de démonstration (Flask + SQLite) pour la consultation
bucco-dentaire : fiche patient, rendez-vous, compte rendu de consultation avec
odontogramme FDI, ordonnance, historique et impression PDF — le tout derrière
une **authentification par comptes nominatifs et mots de passe hachés**.

> ⚠️ **Démonstration technique.** Ce code n'est pas un dispositif médical et
> n'est pas conforme, en l'état, aux exigences applicables aux données de santé
> (RGPD, hébergement HDS, audit de sécurité). Ne l'utilisez pas avec des données
> de patients réelles avant la mise en conformité décrite plus bas.

---

## 1. Installation

```bash
unzip dentaconsult.zip && cd dentaconsult
pip install -r requirements.txt
```

## 2. Créer le premier compte (aucun mot de passe par défaut)

Deux méthodes, au choix — le mot de passe est toujours saisi par vous.

**a) En ligne de commande** (recommandé) :

```bash
flask --app app create-admin
# Identifiant : dr_martin
# Nom complet : Dr Camille Martin
# Mot de passe : **********   (masqué, demandé deux fois)
```

**b) Via le navigateur**, au premier démarrage :

```bash
python app.py     # http://127.0.0.1:5000
```

La page `/setup` s'ouvre automatiquement **tant qu'aucun compte n'existe**, puis
se ferme définitivement. Créez-y le compte administrateur.

Ensuite, les comptes suivants se créent depuis l'écran **Utilisateurs** (réservé
au rôle `admin`).

## 3. Variables d'environnement

| Variable       | Rôle                                              | Défaut |
|----------------|---------------------------------------------------|--------|
| `SECRET_KEY`   | signature des cookies de session — **obligatoire en production**, sinon une clé aléatoire est générée à chaque démarrage (les sessions ne survivent pas au redémarrage) | aléatoire |
| `COOKIE_SECURE`| `1` en production derrière HTTPS (cookie `Secure`)  | `0` |

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export COOKIE_SECURE=1
```

## 4. Ce qui est implémenté côté sécurité

| Mesure | Détail dans le code |
|---|---|
| Hachage des mots de passe | `generate_password_hash(..., method="scrypt")` — scrypt avec sel, jamais de mot de passe en clair ni de SHA nu |
| Vérification | `check_password_hash`, comparaison à temps constant |
| Comptes nominatifs | table `users` : identifiant unique, nom, rôle (`admin` / `praticien` / `secretariat`), état actif, `last_login` |
| Rôles | `login_required` sur toutes les routes, `admin_required` sur l'administration des comptes (403 sinon) |
| Anti-fixation de session | `session.clear()` avant d'ouvrir la session authentifiée |
| CSRF | jeton `secrets.token_urlsafe(32)` lié à la session, champ `_csrf` sur **tous** les formulaires POST, comparaison `hmac.compare_digest`, refus en 400 |
| Verrouillage | 5 échecs → compte verrouillé 15 minutes (`locked_until`), réponse 429 ; l'administrateur peut déverrouiller |
| Anti-énumération | message identique « Identifiant ou mot de passe incorrect » pour un compte inconnu et un mauvais mot de passe |
| Politique de mot de passe | 12 caractères minimum, 3 familles de caractères, refus des mots de passe courants, confirmation obligatoire, refus de réutiliser l'ancien |
| Cookies | `HttpOnly`, `SameSite=Lax`, `Secure` si `COOKIE_SECURE=1`, session limitée à 8 h |
| En-têtes | `Content-Security-Policy` (aucun script inline), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Cache-Control: no-store` |
| Redirections ouvertes | `safe_next()` n'accepte qu'un chemin local |
| Journal d'audit | table `audit_log` : connexions, échecs, verrouillages, refus CSRF, consultations de dossiers, créations/modifications |

## 5. Parcours de consultation pris en charge

1. **Connexion** → tableau de bord (rendez-vous du jour, dernières consultations)
2. **Fiche patient** : identité, coordonnées, N° de sécurité sociale, mutuelle,
   médecin traitant, allergies, antécédents
3. **Rendez-vous** : date/heure, durée, motif, statut (planifié / honoré / annulé)
4. **Consultation** en six étapes : motif → anamnèse → examen clinique →
   odontogramme FDI (32 dents, 7 états) → diagnostic → plan de traitement →
   ordonnance
5. **Compte rendu** : lecture, impression ou export PDF via le navigateur
6. **Historique** : toutes les consultations du patient
7. **Mon compte** : changement de mot de passe (déconnecte la session)
8. **Utilisateurs** (admin) : création, activation/désactivation,
   déverrouillage, réinitialisation de mot de passe, journal d'audit

## 6. Arborescence

```
dentaconsult/
├── app.py                     # routes, schéma, authentification, audit
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html              # navigation + utilisateur connecté + CSRF
│   ├── login.html             # connexion
│   ├── setup.html             # création du premier administrateur
│   ├── account.html           # changement de mot de passe
│   ├── users.html             # gestion des comptes + journal d'audit
│   ├── dashboard.html
│   ├── patients.html
│   ├── patient_form.html
│   ├── patient_detail.html
│   ├── consultation_form.html
│   ├── consultation_view.html
│   ├── appointments.html
│   └── error.html             # 400 / 403 / 404
└── static/
    ├── style.css
    ├── odontogram.js          # script externe (compatible CSP)
    └── ui.js
```

## 7. Démarches projet (de l'idée à la mise en service)

| Étape | Contenu | Livrable |
|-------|---------|----------|
| 1. Cadrage | utilisateurs et rôles, actes couverts, hors-périmètre | note de cadrage 2 pages |
| 2. Conception | modèle de données, écrans, droits d'accès, politique de mot de passe | maquettes + ce prototype |
| 3. Développement | Flask/SQLite → PostgreSQL, journal d'audit, sauvegardes | application |
| 4. Tests | jeux d'essai cliniques, non-régression, test de restauration | rapport de tests |
| 5. Sécurité | HTTPS, revue de code, test d'intrusion, rotation des secrets | dossier sécurité |
| 6. Conformité | registre des traitements, information patient, mentions légales, DPO si nécessaire | registre RGPD |
| 7. Hébergement | prestataire certifié **HDS** (obligatoire pour des données de santé) | contrat d'hébergement |
| 8. Mise en service | formation, comptes nominatifs par membre de l'équipe, reprise du papier | procédure interne |

## 8. Conformité — points à vérifier avant tout usage réel

Cadre **français** ; à confirmer avec votre Ordre et un juriste.

- **Hébergement HDS** : la certification « Hébergeur de Données de Santé » est
  obligatoire lorsqu'un professionnel de santé confie l'hébergement de données de
  santé à caractère personnel à un prestataire
  ([ANS](https://esante.gouv.fr/produits-services/hds)).
- **RGPD** : le RGPD s'applique aux traitements informatiques **et** aux dossiers
  papier ; les patients doivent être informés, mais leur consentement n'est pas
  requis pour le soin ; il n'y a plus de déclaration à la CNIL, mais un
  **registre des traitements** est obligatoire
  ([CNIL — professionnels de santé libéraux](https://www.cnil.fr/fr/rgpd-et-professionnels-de-sante-liberaux-ce-que-vous-devez-savoir)).
  Le consentement explicite redevient nécessaire pour les usages hors soin.
- **Durées de conservation** : fixées par le référentiel CNIL santé et les
  recommandations de l'Ordre — jamais indéfiniment
  ([référentiel CNIL santé](https://www.cnil.fr/sites/cnil/files/atoms/files/referentiel_-_traitements_dans_le_domaine_de_la_sante_hors_recherches.pdf)).
- **Secret professionnel** : imposé au chirurgien-dentiste par l'article
  R.4127-206 du code de la santé publique ; il couvre aussi les accès
  informatiques — d'où les comptes nominatifs et le journal d'audit
  ([code de déontologie](https://www.legifrance.gouv.fr/codes/section_lc/LEGITEXT000006072665/LEGISCTA000006190548/2021-07-11)).

## 9. Ce qu'il reste à faire pour une version de production

- Passer à PostgreSQL (SQLite ne gère pas les accès concurrents d'un cabinet).
- Servir l'application derrière un reverse proxy **HTTPS** avec `COOKIE_SECURE=1`.
- Ajouter une **2FA** (TOTP) pour les comptes administrateurs.
- Limiter les tentatives par adresse IP (Flask-Limiter) en plus du verrouillage par compte.
- Sauvegardes chiffrées et **test de restauration** documenté.
- Purge automatique du journal d'audit selon la durée de conservation retenue.
- Mentions légales, politique de confidentialité, registre des traitements.
- Revue de sécurité externe avant ouverture aux patients.
