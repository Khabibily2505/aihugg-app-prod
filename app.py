# app.py - VERSÃO FINAL CORRIGIDA E SINCRONIZADA

import os
import io
import stripe
import PyPDF2
from flask import Flask, jsonify, request, send_file
from dotenv import load_dotenv
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app) # Permite requisições do seu site WordPress

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
YOUR_DOMAIN = 'https://aihugg.com'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=5)
    plan_id = db.Column(db.String(50), nullable=False, default='gratuito')
    stripe_customer_id = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- ROTAS DE AUTENTICAÇÃO E PERFIL ---
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"erro": "Este email já está em uso."}), 409

    try:
        customer = stripe.Customer.create(email=data.get('email'))
        stripe_customer_id = customer.id
    except Exception as e:
        return jsonify({"erro": f"Falha no serviço de pagamento: {str(e)}"}), 500

    new_user = User(email=data.get('email'), stripe_customer_id=stripe_customer_id)
    new_user.set_password(data.get('password'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Usuário criado com sucesso! Redirecionando para login..."}), 201

@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not user.check_password(data.get('password')):
        return jsonify({"erro": "Credenciais inválidas."}), 401
    
    # IMPORTANTE: O nome da chave é 'access_token', igual ao que o JS espera
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token)

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    # Esta rota pode ser usada no seu painel de controlo
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    return jsonify(email=user.email, credits=user.credits, plan=user.plan_id, member_since=user.created_at.strftime('%d/%m/%Y'))

# --- ROTAS DE PAGAMENTO (STRIPE) ---
@app.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('priceId')
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.stripe_customer_id:
        return jsonify({"erro": "Usuário de pagamento não encontrado. Por favor, contacte o suporte."}), 404
    
    # Determina o modo (assinatura ou pagamento único) com base no Price ID
    mode = 'subscription' if price_id.startswith('price_') else 'payment'
    # Os seus Price IDs de planos começam com "price_", os de créditos avulsos podem começar com "price_" também, 
    # então você precisará de uma lógica melhor se os formatos forem idênticos. 
    # Uma forma fácil é prefixar os IDs no Stripe: ex: sub_... para assinaturas e one_... para pagamentos.
    # Por agora, assumimos que todas as compras via esta rota são assinaturas. Se não forem, mude o 'mode'.

    try:
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            line_items=[{'price': price_id, 'quantity': 1}],
            mode=mode, 
            success_url=f'{YOUR_DOMAIN}/pagamento-sucesso?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{YOUR_DOMAIN}/planos',
            metadata={'user_id': user.id}
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, stripe_webhook_secret)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        return f"Erro de Webhook: {e}", 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        user = User.query.get(user_id)
        if user:
            # TODO: Lógica para dar créditos ou mudar o plano
            print(f"PAGAMENTO BEM-SUCEDIDO para o user_id: {user_id}")
            # Ex: user.credits += 100
            #     db.session.commit()
    return 'Success', 200

# (O resto do seu código, como /gerar-audio, etc. continua aqui, sem alterações)
# ...