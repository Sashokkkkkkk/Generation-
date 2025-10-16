from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import random
import string
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

class PasswordGenerator:
    def __init__(self):
        self.uppercase_chars = string.ascii_uppercase
        self.lowercase_chars = string.ascii_lowercase
        self.number_chars = string.digits
        self.symbol_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    def generate_password(self, length=12, uppercase=True, lowercase=True, 
                         numbers=True, symbols=False):
        charset = ''
        
        if uppercase: charset += self.uppercase_chars
        if lowercase: charset += self.lowercase_chars
        if numbers: charset += self.number_chars
        if symbols: charset += self.symbol_chars
        
        if not charset:
            charset = self.lowercase_chars + self.number_chars
        
        if length < 4: length = 4
        elif length > 50: length = 50
        
        return ''.join(random.choice(charset) for _ in range(length))

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS saved_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            password TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

password_generator = PasswordGenerator()

# Middleware для проверки аутентификации
@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'static']
    if request.endpoint and 'static' not in request.endpoint:
        if not session.get('user_id') and request.endpoint not in allowed_routes:
            return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    initial_password = password_generator.generate_password()
    return render_template('index.html', 
                         initial_password=initial_password,
                         username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            return render_template('auth.html', 
                                 mode='login', 
                                 error='Неверное имя пользователя или пароль')
    
    return render_template('auth.html', mode='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            return render_template('auth.html', 
                                 mode='register', 
                                 error='Пароли не совпадают')
        
        if len(password) < 6:
            return render_template('auth.html', 
                                 mode='register', 
                                 error='Пароль должен содержать минимум 6 символов')
        
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            conn.close()
            
            return redirect(url_for('index'))
            
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('auth.html', 
                                 mode='register', 
                                 error='Пользователь с таким именем или email уже существует')
    
    return render_template('auth.html', mode='register')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/generate', methods=['POST'])
def generate_password():
    if not session.get('user_id'):
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    try:
        data = request.get_json()
        
        if 'custom' in data:
            length = int(data.get('length', 12))
            uppercase = data.get('uppercase', True)
            lowercase = data.get('lowercase', True)
            numbers = data.get('numbers', True)
            symbols = data.get('symbols', False)
            
            password = password_generator.generate_password(
                length=length,
                uppercase=uppercase,
                lowercase=lowercase,
                numbers=numbers,
                symbols=symbols
            )
            
            return jsonify({
                'password': password,
                'settings': {
                    'length': length,
                    'uppercase': uppercase,
                    'lowercase': lowercase,
                    'numbers': numbers,
                    'symbols': symbols
                }
            })
        
        elif 'complexity' in data:
            complexity_level = int(data.get('complexity', 3))
            if complexity_level == 1:
                password = password_generator.generate_password(length=8, uppercase=False, symbols=False)
            elif complexity_level == 2:
                password = password_generator.generate_password(length=12, symbols=False)
            elif complexity_level == 3:
                password = password_generator.generate_password(length=16)
            elif complexity_level == 4:
                password = password_generator.generate_password(length=20, symbols=True)
            else:
                password = password_generator.generate_password(length=24, symbols=True)
            
            return jsonify({'password': password})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/save_password', methods=['POST'])
def save_password():
    if not session.get('user_id'):
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    data = request.get_json()
    password = data.get('password')
    description = data.get('description', '')
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO saved_passwords (user_id, password, description) VALUES (?, ?, ?)',
        (session['user_id'], password, description)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/saved')
def saved_passwords():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    passwords = conn.execute(
        'SELECT * FROM saved_passwords WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    
    return render_template('saved.html', passwords=passwords)

if __name__ == '__main__':
    init_db()
    print("🚀 Запуск генератора паролей с аутентификацией...")
    print("📁 База данных создана")
    print("🌐 Откройте: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)