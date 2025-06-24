# app.py

import os
from flask import Flask, jsonify, request # Adicione 'request'
from dotenv import load_dotenv
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy     # Adicione esta linha
from flask_migrate import Migrate         # Adicione esta linha
from flask_bcrypt import Bcrypt           # Adicione esta linha

load_dotenv()

app = Flask(__name__)

# --- NOVA CONFIGURAÇÃO DE BANCO DE DADOS ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
# -------------------------------------------

# ... (depois da configuração do bcrypt)

# --- MODELO DE DADOS (O ESQUELETO DO BANCO) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=5) # Começa com 5 créditos
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<User {self.email}>'

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# (Restante do seu código com as rotas...)

# (Restante do seu código de configuração do Gemini...)

# Configura a API do Gemini de forma segura
try:
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("ERRO CRÍTICO: A variável de ambiente GEMINI_API_KEY não foi encontrada.")
    genai.configure(api_key=api_key)
except Exception as e:
    print(f"Erro CRÍTICO ao configurar a API do Gemini: {e}")

# --- ROTAS DA APLICAÇÃO ---

@app.route('/')
def index():
    return jsonify({"message": "Bem-vindo à API do AIHugg! Motor online.", "status": "ok"})

@app.route('/testar-resumo', methods=['GET'])
def testar_resumo():
    texto_exemplo = "A inteligência artificial está transformando o mundo."
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"Faça um resumo curto e conciso do seguinte texto: '{texto_exemplo}'"
        response = model.generate_content(prompt)
        return jsonify({"original": texto_exemplo, "resumo": response.text})
    except Exception as e:
        # Este print aparecerá nos logs da Vercel para depuração
        print(f"ERRO REAL ao tentar gerar resumo: {e}")
        return jsonify({"erro": "Ocorreu uma falha interna ao contatar a IA."}), 500

# O Bloco de execução local que a Vercel ignora
if __name__ == '__main__':
    app.run(debug=True)

    # ... (depois da rota /testar-resumo)

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400

    email = data.get('email')
    password = data.get('password')

    # Verifica se o usuário já existe
    if User.query.filter_by(email=email).first():
        return jsonify({"erro": "Este email já está em uso."}), 409 # 409 = Conflito

    # Cria o novo usuário
    new_user = User(email=email)
    new_user.set_password(password) # Criptografa a senha
    
    # Adiciona ao banco de dados
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "Usuário criado com sucesso!",
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "credits": new_user.credits
        }
    }), 201 # 201 = Criado