from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from passlib.context import CryptContext
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], default="pbkdf2_sha256")

class Sistema:
    def __init__(self, db_name):
        self.db_name = db_name

    def _get_db_connection(self):
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        return conn

    def _hash_password(self, password):
        return pwd_context.hash(password)

    def _verify_password(self, password, hashed_password):
        return pwd_context.verify(password, hashed_password)

    def register(self):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if password != confirm_password:
                return render_template('register.html', error='Senhas não coincidem.')

            conn = self._get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()

            if user:
                return render_template('register.html', error='Usuário já existe.')

            hashed_password = self._hash_password(password)

            conn = self._get_db_connection()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()

            return redirect(url_for('login'))
        return render_template('register.html')

    def login(self):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            conn = self._get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()

            if user and self._verify_password(password, user[1]):
                session['logged_in'] = True
                session['username'] = username
                if username == 'admin':
                    session['admin_logged_in'] = True
                    session['admin'] = True
                else:
                    session['admin_logged_in'] = False
                    session['admin'] = False
                return redirect(url_for('index'))
            return render_template('login.html', error='Usuário ou senha inválidos.', register_url=url_for('register'))
        return render_template('login.html')

    def logout(self):
        session.pop('logged_in', None)
        session.pop('username', None)
        session.pop('admin_logged_in', None)
        session.pop('admin', None)
        return redirect(url_for('index'))

   



    def index(self):
        if 'logged_in' in session and session['logged_in']:
            username = session['username']
            if 'admin_logged_in' in session and session['admin_logged_in']:
                return redirect(url_for('admin_menu'))
            else:
                return render_template('index.html', username=username)
        return redirect(url_for('login'))

    def menu(self):
        if 'admin_logged_in' in session and session['admin_logged_in']:
            return redirect(url_for('admin_menu'))
        else:
            return redirect(url_for('index'))
    
    

    def change_password(self):
        if 'admin' in session and session['admin']:
            if request.method == 'POST':
                username = request.form['username']
                old_password = request.form['old_password']
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']

                if new_password != confirm_password:
                    return render_template('change_password.html', error='Senhas não coincidem.')

                conn = self._get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                conn.close()

                if user and self._verify_password(old_password, user[1]):
                    hashed_password = self._hash_password(new_password)
                    conn = self._get_db_connection()
                    conn.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
                    conn.commit()
                    conn.close()
                    return redirect(url_for('menu'))
                return render_template('change_password.html', error='Usuário ou senha inválidos.')
            return render_template('change_password.html')
        return redirect(url_for('index'))

    def change_username(self):
        if 'admin' in session and session['admin']:
            if request.method == 'POST':
                old_username = request.form['old_username']
                new_username = request.form['new_username']

                conn = self._get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE username = ?', (old_username,)).fetchone()
                conn.close()

                if user:
                    conn = self._get_db_connection()
                    conn.execute('UPDATE users SET username = ? WHERE username = ?', (new_username, old_username))
                    conn.commit()
                    conn.close()
                    return redirect(url_for('menu'))
                return render_template('change_username.html', error='Usuário não existe.')
            return render_template('change_username.html')
        return redirect(url_for('index'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session or not session['admin']:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

sistema = Sistema('authe.db')

@app.route('/')
def index():
    return sistema.index()

@app.route('/menu')
def menu():
    return sistema.menu()

@app.route('/register', methods=['GET', 'POST'])
def register():
    return sistema.register()

@app.route('/login', methods=['GET', 'POST'])
def login():
    return sistema.login()

@app.route('/logout')
def logout():
    return sistema.logout()

@app.route('/admin_menu')
@admin_required
def admin_menu():
    return render_template('admin_options.html')

@app.route('/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    return sistema.change_password()

@app.route('/change_username', methods=['GET', 'POST'])
@admin_required
def change_username():
    return sistema.change_username()

if __name__ == "__main__":
    app.run(debug=True)