# app.py - VERSÃO FINAL CORRIGIDA, ROBUSTA E SINCRONIZADA
import os
import stripe
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_cors import CORS

# Carrega variáveis de ambiente do .env
load_dotenv()

app = Flask(__name__)

# --- LINHAS DE DEBUG PARA ADICIONAR ---
# Imprime a DATABASE_URL para os logs da Vercel para depuração.
# ATENÇÃO: Isto irá expor a sua password nos logs. Remova depois de depurar!
import logging
logging.basicConfig(level=logging.DEBUG)
db_url = os.getenv('DATABASE_URL')
logging.debug(f"DATABASE_URL RECEBIDA PELA APLICAÇÃO: {db_url}")
# --------------------------------------

# --- CONFIGURAÇÃO ---
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
# A linha abaixo permanece igual
app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://", 1) if db_url else None
# ... (o resto do código)

# CONFIGURAÇÕES GERAIS (ANTES de instanciar db!)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CORS ACEITANDO TODAS AS ORIGENS NECESSÁRIAS
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://aihugg.com",
            "https://www.aihugg.com",
            "https://aihugg-app-prod.vercel.app",
            "http://localhost:3000",
            "http://127.0.0.1:3000"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"]
    }
})

# Inicialização de serviços
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
YOUR_DOMAIN = 'https://aihugg.com'

# Modelo de usuário
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

# Rota de registro
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
     # 👇 Aqui o contexto da requisição existe. Você pode logar:
    app.logger.error(f"[DEBUG] Payload recebido: {data}")
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"erro": "Este email já está em uso."}), 409

    try:
        customer = stripe.Customer.create(
            email=data.get('email'),
            name=data.get('email').split('@')[0]
        )
        stripe_customer_id = customer.id
    except Exception as e:
        app.logger.error(f"Falha na criação de cliente Stripe: {str(e)}")
        return jsonify({"erro": "Falha no serviço de pagamento. Contacte o suporte."}), 500

    new_user = User(email=data.get('email'), stripe_customer_id=stripe_customer_id)
    new_user.set_password(data.get('password'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Conta criada com sucesso! A redirecionar para login..."}), 201

# Login
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not user.check_password(data.get('password')):
        return jsonify({"erro": "Credenciais inválidas."}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token)

# Perfil
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"erro": "Utilizador não encontrado."}), 404
    return jsonify(
        email=user.email,
        credits=user.credits,
        plan=user.plan_id,
        member_since=user.created_at.strftime('%d/%m/%Y')
    )

# Checkout Stripe
@app.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('priceId')
    user_id = get_jwt_identity()

    if not price_id:
        return jsonify({"erro": "Price ID é obrigatório."}), 400

    user = User.query.get(user_id)
    if not user or not user.stripe_customer_id:
        return jsonify({"erro": "Utilizador de pagamento não encontrado. Contacte o suporte."}), 404

    try:
        price_object = stripe.Price.retrieve(price_id)
        mode = 'subscription' if price_object.type == 'recurring' else 'payment'

        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            line_items=[{'price': price_id, 'quantity': 1}],
            mode=mode,
            success_url=f'{YOUR_DOMAIN}/pagamento-sucesso?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{YOUR_DOMAIN}/planos',
            metadata={'user_id': user.id}
        )
        return jsonify({'url': checkout_session.url})
    except stripe.error.InvalidRequestError:
        return jsonify({"erro": f"Price ID inválido: {price_id}"}), 400
    except Exception as e:
        app.logger.error(f"Erro ao criar sessão de checkout: {str(e)}")
        return jsonify(error={'message': "Falha ao iniciar o processo de pagamento."}), 500

# Funções auxiliares para Webhook
def handle_checkout_session(session):
    user_id = session.get('metadata', {}).get('user_id')
    user = User.query.get(user_id) if user_id else None

    if not user:
        app.logger.error(f"Webhook 'checkout.session.completed' recebeu user_id inválido: {user_id}")
        return

    line_items = stripe.checkout.Session.list_line_items(session.id, limit=1)
    price_id = line_items.data[0].price.id

    if price_id == 'price_ID_PLANO_PRO':
        user.plan_id = 'pro'
        user.credits += 1000
    elif price_id == 'price_ID_PACOTE_500_CREDITOS':
        user.credits += 500

    db.session.commit()
    app.logger.info(f"Pagamento bem-sucedido para user {user_id}.")

def handle_invoice_paid(invoice):
    customer_id = invoice.get('customer')
    user = User.query.filter_by(stripe_customer_id=customer_id).first()

    if not user:
        app.logger.error(f"Webhook 'invoice.payment_succeeded' recebeu customer_id inválido: {customer_id}")
        return

    price_id = invoice['lines']['data'][0]['price']['id']
    if price_id == 'price_ID_PLANO_PRO':
        user.credits += 250

    db.session.commit()
    app.logger.info(f"Renovação de subscrição para user {user.id} bem-sucedida.")

# Webhook do Stripe
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, stripe_webhook_secret)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        app.logger.warning(f"Erro de verificação do Webhook: {e}")
        return "Webhook Error", 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_checkout_session(session)
    elif event['type'] == 'invoice.payment_succeeded':
        invoice = event['data']['object']
        if invoice.get('billing_reason') == 'subscription_cycle':
            handle_invoice_paid(invoice)

    return 'Success', 200

# Executa localmente
# if __name__ == '__main__':
#     app.run(debug=True)
