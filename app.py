# app.py - VERSÃO COMPLETA E ATUALIZADA

import os
import io
import PyPDF2
import stripe # Adicionado para pagamentos

from flask import Flask, jsonify, request, send_file
from dotenv import load_dotenv
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_cors import CORS

# Carrega as variáveis de ambiente do .env
load_dotenv()

# --- CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) 

# Configurações de chaves e base de dados
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização das extensões
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Configuração das APIs Externas
try:
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
except Exception as e:
    print(f"Erro CRÍTICO ao configurar APIs externas: {e}")

stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

# --- MODELO DE DADOS (DATABASE) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=5)
    current_plan = db.Column(db.String(50), nullable=True, default='Gratuito') # Para guardar o nome do plano
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- MAPA DE PRODUTOS STRIPE ---
# !! IMPORTANTE: Substitua 'price_...' pelos IDs de Preço REAIS do seu painel Stripe !!
PRODUCT_MAP = {
    # --- Planos de Assinatura Mensal ---
    "price_1PG...": {"type": "plan", "name": "Entrada", "credits": 35},
    "price_1PG...": {"type": "plan", "name": "Iniciante", "credits": 15}, #+bônus
    "price_1PG...": {"type": "plan", "name": "Leitor", "credits": 40},
    "price_1PG...": {"type": "plan", "name": "Criador", "credits": 80},
    "price_1PG...": {"type": "plan", "name": "Império", "credits": 150},
    # --- Pacotes de Créditos Avulsos ---
    "price_1PG...": {"type": "credits", "name": "Recarga Rápida", "credits": 15},
    "price_1PG...": {"type": "credits", "name": "Recarga Padrão", "credits": 30},
    "price_1PG...": {"type": "credits", "name": "Recarga Essencial", "credits": 70},
    "price_1PG...": {"type": "credits", "name": "Recarga Inteligente", "credits": 100},
    "price_1PG...": {"type": "credits", "name": "Recarga Avançada", "credits": 150},
    "price_1PG...": {"type": "credits", "name": "Recarga Profissional", "credits": 250},
}


# --- ROTAS DE AUTENTICAÇÃO E PERFIL ---
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"erro": "Este email já está em uso."}), 409
    new_user = User(email=data.get('email'))
    new_user.set_password(data.get('password'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Usuário criado com sucesso!"}), 201

@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not user.check_password(data.get('password')):
        return jsonify({"erro": "Credenciais inválidas."}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token})

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    return jsonify({
        "email": user.email, 
        "credits": user.credits, 
        "current_plan": user.current_plan,
        "member_since": user.created_at.strftime('%d/%m/%Y')
    })

# --- ROTAS DE PAGAMENTO (STRIPE) ---

@app.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('priceId')
    if not price_id or price_id not in PRODUCT_MAP:
        return jsonify({"erro": "ID do preço é inválido ou obrigatório."}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    product_details = PRODUCT_MAP.get(price_id)
    mode = "subscription" if product_details['type'] == 'plan' else "payment"

    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{'price': price_id, 'quantity': 1}],
            mode=mode,
            success_url='https://aihugg.com/dashboard?pagamento=sucesso', # Altere para a sua página de sucesso
            cancel_url='https://aihugg.com/planos',
            customer_email=user.email,
            metadata={'user_id': user.id, 'price_id': price_id}
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, stripe_webhook_secret)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        print(f"ERRO no Webhook: {e}")
        return 'Erro de assinatura ou payload inválido', 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        metadata = session.get('metadata', {})
        user_id = metadata.get('user_id')
        price_id = metadata.get('price_id')

        if not user_id or not price_id:
            print("ERRO no Webhook: Metadados 'user_id' ou 'price_id' em falta.")
            return "Erro: Metadados em falta.", 400

        plan_details = PRODUCT_MAP.get(price_id)
        if not plan_details:
            print(f"ERRO no Webhook: price_id '{price_id}' não encontrado no PRODUCT_MAP.")
            return "Erro: Produto não encontrado.", 400

        user = User.query.get(user_id)
        if user:
            user.credits += plan_details['credits']
            if plan_details['type'] == 'plan':
                user.current_plan = plan_details['name']
            db.session.commit()
            print(f"SUCESSO Webhook: {plan_details['credits']} créditos adicionados ao utilizador {user.email}.")
        else:
            print(f"ERRO CRÍTICO no Webhook: Utilizador ID {user_id} não encontrado na base de dados.")
    
    return 'Sucesso', 200

# --- ROTAS PRINCIPAIS DA APLICAÇÃO (CORE) ---

# (O seu código de extração de PDF e geração de áudio continua aqui, sem alterações)
def extrair_texto_de_pdf(arquivo_pdf_em_memoria):
    # Seu código aqui (indentado)
    texto = "exemplo de texto extraído"
    return texto

def gerar_resumo_com_gemini(texto_completo):
    # Se não implementou, coloque pass
    pass

def gerar_audio_do_texto(texto_resumo):
    # Código para gerar audio
    pass

@app.route('/gerar-audio', methods=['POST'])
@jwt_required()
def gerar_audio_endpoint():
    # ... seu código para gerar áudio permanece o mesmo ...
    # Ele já debita os créditos corretamente.
    pass # Remova este 'pass' e mantenha o seu código original aqui

# --- INICIALIZAÇÃO DA APLICAÇÃO ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)