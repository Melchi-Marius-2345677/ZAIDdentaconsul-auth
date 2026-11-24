"""
DentaConsult — application de consultation bucco-dentaire.

Authentification : comptes nominatifs en base, mots de passe hachés
(scrypt via Werkzeug), CSRF sur tous les formulaires, verrouillage après
échecs répétés, journal d'audit, cookies HttpOnly / SameSite.

Lancement :
    flask --app app create-admin        # crée le premier compte (interactif)
    python app.py                       # -> http://127.0.0.1:5000
    # ou, au premier démarrage : http://127.0.0.1:5000/setup

Variables d'environnement :
    SECRET_KEY     clé de signature des cookies de session (obligatoire en prod)
    COOKIE_SECURE  "1" en production derrière HTTPS

AVERTISSEMENT : projet de démonstration. Avant tout usage avec de vraies
données de patients : hébergement certifié HDS, RGPD, audit de sécurité.
"""

import hmac
import json
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from functools import wraps

import click
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "dentaconsult.db")

# --- Politique de sécurité -------------------------------------------------
PASSWORD_MIN = 12          # longueur minimale
MAX_ATTEMPTS = 5           # échecs avant verrouillage
LOCK_MINUTES = 15          # durée du verrouillage
SESSION_HOURS = 8          # durée d'une session
HASH_METHOD = "scrypt"     # jamais de mot de passe en clair, jamais de SHA nu

app = Flask(__name__)
app.config.update(
    # Fallback aléatoire : les sessions survivent à un redémarrage uniquement
    # si SECRET_KEY est fournie par l'environnement.
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

# ---------------------------------------------------------------------------
# Schéma dentaire FDI
# ---------------------------------------------------------------------------
TEETH = [
    ("Maxillaire droit", ["18", "17", "16", "15", "14", "13", "12", "11"]),
    ("Maxillaire gauche", ["21", "22", "23", "24", "25", "26", "27", "28"]),
    ("Mandibule droite", ["48", "47", "46", "45", "44", "43", "42", "41"]),
    ("Mandibule gauche", ["31", "32", "33", "34", "35", "36", "37", "38"]),
]

TEETH_STATES = [
    ("sain", "Sain"),
    ("carie", "Carie"),
    ("obturation", "Obturation / soin"),
    ("couronne", "Couronne"),
    ("absent", "Absente / extraite"),
    ("implant", "Implant"),
    ("prothese", "Prothèse"),
]
STATE_LABELS = dict(TEETH_STATES)

# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    nom_complet    TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT 'praticien',   -- admin | praticien | secretariat
    actif          INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT,
    last_login     TEXT,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    username TEXT,
    action   TEXT NOT NULL,
    ip       TEXT,
    detail   TEXT
);

CREATE TABLE IF NOT EXISTS patients (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    nom           TEXT NOT NULL,
    prenom        TEXT NOT NULL,
    date_naissance TEXT,
    sexe          TEXT,
    telephone     TEXT,
    email         TEXT,
    adresse       TEXT,
    num_secu      TEXT,
    mutuelle      TEXT,
    medecin       TEXT,
    allergies     TEXT,
    antecedents   TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS appointments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    rdv_date   TEXT NOT NULL,
    duree      INTEGER DEFAULT 30,
    motif      TEXT,
    statut     TEXT DEFAULT 'planifie',
    notes      TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS consultations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id   INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    date_consult TEXT NOT NULL,
    praticien    TEXT,
    motif        TEXT,
    anamnese     TEXT,
    examen       TEXT,
    odontogramme TEXT DEFAULT '{}',
    diagnostic   TEXT,
    plan         TEXT,
    ordonnance   TEXT,
    notes        TEXT,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_consult_patient ON consultations(patient_id);
CREATE INDEX IF NOT EXISTS idx_rdv_patient ON appointments(patient_id);
"""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().replace(microsecond=0).isoformat()


def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log_event(action: str, detail: str = "", username: str | None = None) -> None:
    """Journal d'audit : qui a fait quoi, quand, depuis quelle adresse."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (ts, username, action, ip, detail) VALUES (?,?,?,?,?)",
            (now_iso(), username or session.get("username") or "—", action,
             request.remote_addr if request else None, detail),
        )
        db.commit()
    except sqlite3.Error:
        pass  # un échec de journalisation ne doit pas casser la requête


def seed_demo() -> None:
    """Un patient de démonstration si la base est vide (aucun compte créé ici)."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    if con.execute("SELECT COUNT(*) c FROM patients").fetchone()["c"] == 0:
        cur = con.execute(
            """INSERT INTO patients (nom, prenom, date_naissance, sexe, telephone,
               email, adresse, num_secu, mutuelle, allergies, antecedents)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ("Martin", "Camille", "1988-04-12", "F", "06 12 34 56 78",
             "camille.martin@example.com", "12 rue des Lilas, 75011 Paris",
             "2 88 04 75 116 042 33", "Mutuelle Générale",
             "Pénicilline (éruption cutanée)",
             "Asthme léger — ventoline à la demande. Pas d'anticoagulant."))
        con.execute(
            """INSERT INTO appointments (patient_id, rdv_date, duree, motif, statut)
               VALUES (?,?,?,?,?)""",
            (cur.lastrowid, datetime.now().strftime("%Y-%m-%dT%H:%M"), 30,
             "Douleur molaire inférieure droite", "planifie"))
        con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Mots de passe
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return check_password_hash(password_hash, password)
    except (ValueError, TypeError):
        return False


def password_errors(password: str, confirmation: str | None = None) -> list[str]:
    """Renvoie la liste des motifs de refus (vide = mot de passe accepté)."""
    errs = []
    if len(password or "") < PASSWORD_MIN:
        errs.append(f"Le mot de passe doit contenir au moins {PASSWORD_MIN} caractères.")
    categories = sum(bool(any(c.islower() for c in pw))
                     for pw in [password or ""])
    pw = password or ""
    kinds = [
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ]
    if sum(kinds) < 3:
        errs.append("Il doit mélanger au moins trois types de caractères "
                    "(minuscules, majuscules, chiffres, symboles).")
    if pw.lower() in {"motdepasse", "password", "dentaconsult", "azertyuiop123"}:
        errs.append("Ce mot de passe est trop courant.")
    if confirmation is not None and password != confirmation:
        errs.append("Les deux mots de passe ne correspondent pas.")
    return errs


# ---------------------------------------------------------------------------
# Sessions, CSRF, contrôles d'accès
# ---------------------------------------------------------------------------
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.context_processor
def inject_session():
    return {"pwd_min": PASSWORD_MIN}


@app.before_request
def csrf_protect():
    """Toute requête modificatrice doit porter un jeton lié à la session.

    Les pages publiques (connexion, premier démarrage) sont aussi protégées.
    En revanche, un visiteur non connecté est renvoyé vers la page de connexion
    par `login_required` plutôt que de recevoir une erreur CSRF.
    """
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not session.get("user_id") and request.endpoint not in ("login", "setup"):
            return None
        attendu = session.get("_csrf")
        recu = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        if not attendu or not recu or not hmac.compare_digest(attendu, recu):
            log_event("csrf_refuse", f"{request.method} {request.path}")
            abort(400, description="Jeton CSRF absent ou invalide.")


@app.before_request
def refresh_session():
    if session.get("user_id"):
        session.permanent = True
        session.modified = True


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; form-action 'self'; base-uri 'none'; "
        "frame-ancestors 'none'")
    if request.endpoint not in ("static",):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def safe_next(target: str | None) -> str | None:
    """Évite les redirections ouvertes : chemin local uniquement."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Création du premier administrateur, uniquement si aucun compte n'existe."""
    db = get_db()
    if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        nom = (request.form.get("nom_complet") or "").strip()
        pw = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        errs = password_errors(pw, pw2)
        if not username.isidentifier() or len(username) < 3:
            errs.append("L'identifiant doit faire au moins 3 caractères "
                        "(lettres, chiffres, tiret bas).")
        if not nom:
            errs.append("Le nom du praticien est requis.")
        if errs:
            for e in errs:
                flash(e, "error")
        else:
            db.execute(
                """INSERT INTO users (username, password_hash, nom_complet, role)
                   VALUES (?,?,?, 'admin')""",
                (username, hash_password(pw), nom))
            db.commit()
            log_event("compte_cree", f"premier administrateur « {username} »",
                      username=username)
            flash("Compte administrateur créé. Vous pouvez vous connecter.", "success")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        return redirect(url_for("setup"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        user = db.execute(
            "SELECT * FROM users WHERE lower(username) = ?", (username,)).fetchone()

        # Message volontairement générique : on n'indique pas si le compte existe.
        generic = "Identifiant ou mot de passe incorrect."

        if user is None:
            log_event("echec_connexion", "identifiant inconnu", username=username or "—")
            flash(generic, "error")
            return render_template("login.html"), 401

        if user["locked_until"]:
            try:
                until = datetime.fromisoformat(user["locked_until"])
            except ValueError:
                until = None
            if until and now_utc() < until:
                restant = max(1, int((until - now_utc()).total_seconds() // 60) + 1)
                log_event("connexion_bloquee", "compte verrouillé", username=username)
                flash(f"Compte verrouillé après trop d'échecs. "
                      f"Réessayez dans {restant} minute(s).", "error")
                return render_template("login.html"), 429
            db.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 "
                       "WHERE id = ?", (user["id"],))
            db.commit()

        if not user["actif"]:
            log_event("connexion_refusee", "compte désactivé", username=username)
            flash("Ce compte est désactivé. Contactez l'administrateur.", "error")
            return render_template("login.html"), 403

        if not verify_password(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_ATTEMPTS:
                until = (now_utc() + timedelta(minutes=LOCK_MINUTES)).replace(microsecond=0)
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                           (attempts, until.isoformat(), user["id"]))
                db.commit()
                log_event("compte_verrouille", f"{attempts} échecs", username=username)
                flash(f"Trop d'échecs : compte verrouillé {LOCK_MINUTES} minutes.", "error")
                return render_template("login.html"), 429
            db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?",
                       (attempts, user["id"]))
            db.commit()
            log_event("echec_connexion", f"mot de passe erroné ({attempts}/{MAX_ATTEMPTS})",
                      username=username)
            flash(generic, "error")
            return render_template("login.html"), 401

        # Succès : on repart d'une session neuve (anti-fixation de session).
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["nom_complet"] = user["nom_complet"] or user["username"]
        session["role"] = user["role"]
        session.permanent = True
        csrf_token()
        db.execute("""UPDATE users SET failed_attempts = 0, locked_until = NULL,
                      last_login = ? WHERE id = ?""", (now_iso(), user["id"]))
        db.commit()
        log_event("connexion", f"rôle {user['role']}")
        flash(f"Bienvenue, {session['nom_complet']}.", "success")
        return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))

    return render_template("login.html")


@app.route("/deconnexion", methods=["POST"])
@login_required
def logout():
    log_event("deconnexion")
    session.clear()
    flash("Vous êtes déconnecté.", "success")
    return redirect(url_for("login"))


@app.route("/mon-compte", methods=["GET", "POST"])
@login_required
def account():
    db = get_db()
    if request.method == "POST":
        current = request.form.get("current") or ""
        pw = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        user = db.execute("SELECT * FROM users WHERE id = ?",
                          (session["user_id"],)).fetchone()
        errs = []
        if not verify_password(user["password_hash"], current):
            errs.append("Le mot de passe actuel est incorrect.")
        if current and pw == current:
            errs.append("Le nouveau mot de passe doit être différent de l'ancien.")
        errs += password_errors(pw, pw2)
        if errs:
            for e in errs:
                flash(e, "error")
        else:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (hash_password(pw), user["id"]))
            db.commit()
            log_event("mot_de_passe_change")
            session.clear()
            flash("Mot de passe modifié. Reconnectez-vous.", "success")
            return redirect(url_for("login"))
    user = db.execute("SELECT * FROM users WHERE id = ?",
                      (session["user_id"],)).fetchone()
    return render_template("account.html", user=user, pwd_min=PASSWORD_MIN)


# ---------------------------------------------------------------------------
# Administration des comptes
# ---------------------------------------------------------------------------
@app.route("/utilisateurs")
@login_required
@admin_required
def users():
    db = get_db()
    liste = db.execute(
        "SELECT * FROM users ORDER BY role, username").fetchall()
    journal = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 12").fetchall()
    return render_template("users.html", users=liste, journal=journal,
                           pwd_min=PASSWORD_MIN)


@app.route("/utilisateurs/nouveau", methods=["POST"])
@login_required
@admin_required
def user_new():
    db = get_db()
    username = (request.form.get("username") or "").strip().lower()
    nom = (request.form.get("nom_complet") or "").strip()
    role = request.form.get("role") or "praticien"
    pw = request.form.get("password") or ""
    pw2 = request.form.get("password2") or ""

    errs = password_errors(pw, pw2)
    if role not in ("admin", "praticien", "secretariat"):
        errs.append("Rôle inconnu.")
    if not username.isidentifier() or len(username) < 3:
        errs.append("Identifiant invalide (3 caractères minimum, "
                    "lettres/chiffres/tiret bas).")
    if not nom:
        errs.append("Le nom complet est requis.")
    if db.execute("SELECT 1 FROM users WHERE lower(username) = ?",
                  (username,)).fetchone():
        errs.append("Cet identifiant existe déjà.")
    if errs:
        for e in errs:
            flash(e, "error")
    else:
        db.execute("""INSERT INTO users (username, password_hash, nom_complet, role)
                      VALUES (?,?,?,?)""",
                   (username, hash_password(pw), nom, role))
        db.commit()
        log_event("compte_cree", f"{username} ({role})")
        flash(f"Compte « {username} » créé.", "success")
    return redirect(url_for("users"))


@app.route("/utilisateurs/<int:uid>/<action>", methods=["POST"])
@login_required
@admin_required
def user_admin_action(uid, action):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None:
        abort(404)
    if action == "activer":
        db.execute("UPDATE users SET actif = 1 WHERE id = ?", (uid,))
        log_event("compte_active", user["username"])
    elif action == "desactiver":
        if uid == session.get("user_id"):
            flash("Vous ne pouvez pas désactiver votre propre compte.", "error")
            return redirect(url_for("users"))
        db.execute("UPDATE users SET actif = 0 WHERE id = ?", (uid,))
        log_event("compte_desactive", user["username"])
    elif action == "deverrouiller":
        db.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 "
                   "WHERE id = ?", (uid,))
        log_event("compte_deverrouille", user["username"])
    elif action == "mot-de-passe":
        pw = request.form.get("password") or ""
        errs = password_errors(pw, request.form.get("password2") or "")
        if errs:
            for e in errs:
                flash(e, "error")
            return redirect(url_for("users"))
        db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, "
                   "locked_until = NULL WHERE id = ?",
                   (hash_password(pw), uid))
        log_event("mot_de_passe_reinitialise", user["username"])
        flash(f"Mot de passe de « {user['username']} » réinitialisé.", "success")
    else:
        abort(404)
    db.commit()
    if action in ("activer", "desactiver", "deverrouiller"):
        flash("Compte mis à jour.", "success")
    return redirect(url_for("users"))


# ---------------------------------------------------------------------------
# Tableau de bord
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    stats = {
        "patients": db.execute("SELECT COUNT(*) c FROM patients").fetchone()["c"],
        "rdv_jour": db.execute(
            "SELECT COUNT(*) c FROM appointments WHERE date(rdv_date) = date('now')"
        ).fetchone()["c"],
        "consultations": db.execute("SELECT COUNT(*) c FROM consultations").fetchone()["c"],
    }
    rdv = db.execute(
        """SELECT a.*, p.nom, p.prenom FROM appointments a
           JOIN patients p ON p.id = a.patient_id
           WHERE a.statut = 'planifie'
           ORDER BY a.rdv_date ASC LIMIT 6""").fetchall()
    recentes = db.execute(
        """SELECT c.*, p.nom, p.prenom FROM consultations c
           JOIN patients p ON p.id = c.patient_id
           ORDER BY c.date_consult DESC, c.id DESC LIMIT 5""").fetchall()
    return render_template("dashboard.html", stats=stats, rdv=rdv, recentes=recentes)


# ---------------------------------------------------------------------------
# Patients
# ---------------------------------------------------------------------------
CHAMPS_PATIENT = ("nom", "prenom", "date_naissance", "sexe", "telephone", "email",
                  "adresse", "num_secu", "mutuelle", "medecin", "allergies",
                  "antecedents")


@app.route("/patients")
@login_required
def patients():
    q = (request.args.get("q") or "").strip()
    db = get_db()
    if q:
        rows = db.execute(
            """SELECT * FROM patients WHERE nom LIKE ? OR prenom LIKE ?
               OR telephone LIKE ? ORDER BY nom, prenom""",
            (f"%{q}%",) * 3).fetchall()
    else:
        rows = db.execute("SELECT * FROM patients ORDER BY nom, prenom").fetchall()
    return render_template("patients.html", patients=rows, q=q)


@app.route("/patients/nouveau", methods=["GET", "POST"])
@login_required
def patient_new():
    if request.method == "POST":
        db = get_db()
        cur = db.execute(
            f"INSERT INTO patients ({', '.join(CHAMPS_PATIENT)}) "
            f"VALUES ({', '.join('?' * len(CHAMPS_PATIENT))})",
            tuple(request.form.get(k, "").strip() for k in CHAMPS_PATIENT))
        db.commit()
        log_event("patient_cree", f"id {cur.lastrowid}")
        flash("Fiche patient créée.", "success")
        return redirect(url_for("patient_detail", pid=cur.lastrowid))
    return render_template("patient_form.html", patient=None)


@app.route("/patients/<int:pid>")
@login_required
def patient_detail(pid):
    db = get_db()
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (pid,)).fetchone()
    if patient is None:
        flash("Patient introuvable.", "error")
        return redirect(url_for("patients"))
    consultations = db.execute(
        "SELECT * FROM consultations WHERE patient_id = ? "
        "ORDER BY date_consult DESC, id DESC", (pid,)).fetchall()
    rdvs = db.execute(
        """SELECT * FROM appointments WHERE patient_id = ?
           AND date(rdv_date) >= date('now') ORDER BY rdv_date ASC""",
        (pid,)).fetchall()
    log_event("dossier_consulte", f"patient id {pid}")
    return render_template("patient_detail.html", patient=patient,
                           consultations=consultations, rdvs=rdvs)


@app.route("/patients/<int:pid>/modifier", methods=["GET", "POST"])
@login_required
def patient_edit(pid):
    db = get_db()
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (pid,)).fetchone()
    if patient is None:
        return redirect(url_for("patients"))
    if request.method == "POST":
        db.execute(
            f"UPDATE patients SET {', '.join(c + ' = ?' for c in CHAMPS_PATIENT)} "
            "WHERE id = ?",
            tuple(request.form.get(k, "").strip() for k in CHAMPS_PATIENT) + (pid,))
        db.commit()
        log_event("patient_modifie", f"patient id {pid}")
        flash("Fiche patient mise à jour.", "success")
        return redirect(url_for("patient_detail", pid=pid))
    return render_template("patient_form.html", patient=patient)


# ---------------------------------------------------------------------------
# Consultations
# ---------------------------------------------------------------------------
@app.route("/patients/<int:pid>/consultation", methods=["GET", "POST"])
@login_required
def consultation_new(pid):
    db = get_db()
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (pid,)).fetchone()
    if patient is None:
        return redirect(url_for("patients"))

    if request.method == "POST":
        odo = request.form.get("odontogramme") or "{}"
        try:
            json.loads(odo)
        except json.JSONDecodeError:
            odo = "{}"
        cur = db.execute(
            """INSERT INTO consultations (patient_id, date_consult, praticien, motif,
               anamnese, examen, odontogramme, diagnostic, plan, ordonnance, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (pid,
             request.form.get("date_consult") or datetime.now().strftime("%Y-%m-%d"),
             request.form.get("praticien", "").strip() or session.get("nom_complet", ""),
             request.form.get("motif", "").strip(),
             request.form.get("anamnese", "").strip(),
             request.form.get("examen", "").strip(), odo,
             request.form.get("diagnostic", "").strip(),
             request.form.get("plan", "").strip(),
             request.form.get("ordonnance", "").strip(),
             request.form.get("notes", "").strip()))
        db.commit()
        log_event("consultation_creee", f"id {cur.lastrowid} (patient {pid})")
        flash("Consultation enregistrée.", "success")
        return redirect(url_for("consultation_view", cid=cur.lastrowid))

    return render_template("consultation_form.html", patient=patient,
                           today=datetime.now().strftime("%Y-%m-%d"),
                           teeth=TEETH, states=TEETH_STATES)


@app.route("/consultations/<int:cid>")
@login_required
def consultation_view(cid):
    db = get_db()
    c = db.execute("SELECT * FROM consultations WHERE id = ?", (cid,)).fetchone()
    if c is None:
        flash("Consultation introuvable.", "error")
        return redirect(url_for("dashboard"))
    p = db.execute("SELECT * FROM patients WHERE id = ?",
                   (c["patient_id"],)).fetchone()
    try:
        odo = json.loads(c["odontogramme"] or "{}")
    except json.JSONDecodeError:
        odo = {}
    return render_template("consultation_view.html", c=c, patient=p,
                           teeth=TEETH, odo=odo, state_labels=STATE_LABELS)


# ---------------------------------------------------------------------------
# Rendez-vous
# ---------------------------------------------------------------------------
@app.route("/rendez-vous", methods=["GET", "POST"])
@login_required
def appointments():
    db = get_db()
    if request.method == "POST":
        pid = request.form.get("patient_id")
        if not pid:
            flash("Choisissez un patient.", "error")
        else:
            db.execute(
                """INSERT INTO appointments (patient_id, rdv_date, duree, motif, notes)
                   VALUES (?,?,?,?,?)""",
                (pid, request.form.get("rdv_date"),
                 int(request.form.get("duree") or 30),
                 request.form.get("motif", "").strip(),
                 request.form.get("notes", "").strip()))
            db.commit()
            log_event("rdv_cree", f"patient {pid}")
            flash("Rendez-vous enregistré.", "success")
            return redirect(url_for("appointments"))

    liste = db.execute(
        """SELECT a.*, p.nom, p.prenom FROM appointments a
           JOIN patients p ON p.id = a.patient_id
           ORDER BY (a.statut <> 'planifie'), a.rdv_date ASC""").fetchall()
    pats = db.execute("SELECT id, nom, prenom FROM patients ORDER BY nom").fetchall()
    return render_template("appointments.html", liste=liste, patients=pats)


@app.route("/rendez-vous/<int:rid>/<statut>", methods=["POST"])
@login_required
def appointment_status(rid, statut):
    if statut not in ("planifie", "honore", "annule"):
        statut = "planifie"
    db = get_db()
    db.execute("UPDATE appointments SET statut = ? WHERE id = ?", (statut, rid))
    db.commit()
    log_event("rdv_statut", f"rdv {rid} -> {statut}")
    flash("Statut du rendez-vous mis à jour.", "success")
    return redirect(request.referrer or url_for("appointments"))


@app.errorhandler(400)
def bad_request(err):
    return render_template("error.html", code=400,
                           message=getattr(err, "description",
                                           "Requête invalide.")), 400


@app.errorhandler(403)
def forbidden(_err):
    return render_template("error.html", code=403,
                           message="Accès refusé : votre rôle ne permet pas "
                                   "cette action."), 403


@app.errorhandler(404)
def not_found(_err):
    return render_template("error.html", code=404,
                           message="Page introuvable."), 404


# ---------------------------------------------------------------------------
# Création du premier compte en ligne de commande
# ---------------------------------------------------------------------------
@app.cli.command("create-admin")
@click.option("--username", prompt="Identifiant")
@click.option("--nom", prompt="Nom complet")
@click.option("--password", prompt="Mot de passe", hide_input=True,
              confirmation_prompt="Confirmer le mot de passe")
def create_admin_cli(username, nom, password):
    """Crée un compte administrateur (aucun mot de passe par défaut)."""
    errs = password_errors(password)
    if errs:
        for e in errs:
            click.echo(f"✗ {e}", err=True)
        sys.exit(1)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    username = username.strip().lower()
    if db.execute("SELECT 1 FROM users WHERE lower(username) = ?",
                  (username,)).fetchone():
        click.echo("✗ Cet identifiant existe déjà.", err=True)
        sys.exit(1)
    db.execute("INSERT INTO users (username, password_hash, nom_complet, role) "
               "VALUES (?,?,?, 'admin')",
               (username, hash_password(password), nom.strip() or username))
    db.commit()
    db.close()
    click.echo(f"✓ Compte administrateur « {username} » créé.")


init_db()
seed_demo()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
