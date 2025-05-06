from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = 'secret123'  # à personnaliser pour la sécurité

# Créer la base de données si elle n'existe pas
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Validation stricte ASCII de l'email
def is_valid_ascii_email(email):
    # Format basique ASCII-only : user@domain.tld
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.fullmatch(pattern, email))

@app.route('/')
def home():
    if 'username' in session:
        return f"Bienvenue, {session['username']}! <a href='/logout'>Déconnexion</a>"
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not re.match(r'^[a-zA-Z0-9_.-]{3,20}$', username):
            flash('Nom d’utilisateur invalide (3-20 caractères, lettres, chiffres, _.-)')
        elif not is_valid_ascii_email(email):
            flash('Adresse e-mail invalide (seuls les caractères ASCII sont autorisés).')
        elif len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.')
        else:
            hashed_pw = generate_password_hash(password)
            try:
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_pw))
                conn.commit()
                conn.close()
                flash('Compte créé avec succès ! Veuillez vous connecter.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Nom d’utilisateur ou email déjà utilisé.')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identity = request.form['username_or_email'].strip()
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identity, identity))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):  # user[3] = password
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash('Identifiants invalides.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Veuillez vous connecter pour accéder au tableau de bord.", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
