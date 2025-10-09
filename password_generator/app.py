from flask import Flask, render_template, request, jsonify
import random
import string
import os

app = Flask(__name__)

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

password_generator = PasswordGenerator()

@app.route('/')
def index():
    initial_password = password_generator.generate_password()
    print(f"Генерируем пароль: {initial_password}")  # Для отладки
    return render_template('index.html', initial_password=initial_password)

@app.route('/generate', methods=['POST'])
def generate_password():
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
            # Простая реализация сложности
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

if __name__ == '__main__':
    print("🚀 Запуск генератора паролей...")
    print("📁 Текущая директория:", os.getcwd())
    print("🌐 Откройте: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)