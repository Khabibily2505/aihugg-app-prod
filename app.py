# app.py - VERSÃO ORIGINAL DO UTILIZADOR, COM CORREÇÕES PONTUAIS APLICADAS

import os
import io
import json
import PyPDF2
from flask import Flask, jsonify, request, send_file, redirect
from dotenv import load_dotenv
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_cors import CORS
import stripe

# Carrega as variáveis de ambiente do .env
load_dotenv()

# --- CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__)

# --- ALTERAÇÃO 5: CORS MAIS SEGURO ---
# Permite requisições apenas do seu frontend (definido nas variáveis de ambiente)
CORS(app, resources={r"/*": {"origins": os.getenv("FRONTEND_URL")}})

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURAÇÃO DO STRIPE ---
stripe.api_key = os.getenv('STRIPE_API_SECRET_KEY')
stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

# Inicialização das extensões
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Configuração da API do Gemini
try:
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
except Exception as e:
    app.logger.error(f"Erro CRÍTICO ao configurar a API do Gemini: {e}")

# --- MODELO DE DADOS (COM MAPEAMENTO DE PRODUTOS) ---
# --- ALTERAÇÃO 1: CAMPOS ADICIONADOS AO MODELO USER ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=5)
    plan = db.Column(db.String(50), default="Gratuito") # Para guardar o nome do plano atual
    stripe_customer_id = db.Column(db.String(120), unique=True, nullable=True) # Para ligar ao Stripe
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# Seu mapeamento de IDs está perfeito. Nenhuma alteração aqui.
PRICE_ID_TO_CREDITS = {
    "price_1ReHqmF4Pfx9Nag9Srxn2ptJ": {"type": "plan", "name": "Entrada", "credits": 35},
    "price_1ReHrOF4Pfx9Nag98bnQTNDz": {"type": "plan", "name": "Iniciante", "credits": 15},
    "price_1ReHs1F4Pfx9Nag9o95BatBV": {"type": "plan", "name": "Leitor", "credits": 40},
    "price_1ReHsdF4Pfx9Nag9CrogYmaN": {"type": "plan", "name": "Criador", "credits": 80},
    "price_1ReHtOF4Pfx9Nag9Z2kRM9H2": {"type": "plan", "name": "Império", "credits": 150},
    "price_1ReHuGF4Pfx9Nag9LYN2cJhA": {"type": "credits", "name": "Recarga Rápida", "credits": 15},
    "price_1ReHvHF4Pfx9Nag9eOmQEvHK": {"type": "credits", "name": "Recarga Padrão", "credits": 30},
    "price_1ReHvwF4Pfx9Nag95iQRpo1L": {"type": "credits", "name": "Recarga Essencial", "credits": 70},
    "price_1ReHwZF4Pfx9Nag94G2eQua6": {"type": "credits", "name": "Recarga Inteligente", "credits": 100},
    "price_1ReHxMF4Pfx9Nag9A6XhifA8": {"type": "credits", "name": "Recarga Avançada", "credits": 150},
    "price_1ReHynF4Pfx9Nag941RzJPN2": {"type": "credits", "name": "Recarga Profissional", "credits": 250},
}

# --- ROTAS DE AUTENTICAÇÃO E PERFIL ---
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"erro": "Este email já está em uso."}), 409
    
    # --- ALTERAÇÃO 2: CRIA UM CLIENTE NO STRIPE DURANTE O REGISTO ---
    try:
        customer = stripe.Customer.create(email=data.get('email'))
        stripe_customer_id = customer.id
    except Exception as e:
        app.logger.error(f"Erro ao criar cliente Stripe para {data.get('email')}: {e}")
        return jsonify({"erro": "Falha no registo do sistema de pagamento."}), 500

    new_user = User(
        email=data.get('email'), 
        stripe_customer_id=stripe_customer_id # Salva o ID do cliente Stripe
    )
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
    
    # Usa o ID inteiro do usuário, que é mais robusto.
    access_token = create_access_token(identity=user.id) 
    return jsonify({"access_token": access_token})

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        user_id = int(get_jwt_identity())
    except (ValueError, TypeError):
        return jsonify({"erro": "Token de usuário inválido."}), 422
        
    user = User.query.get(user_id)
    if not user:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    return jsonify({
        "email": user.email,
        "credits": user.credits,
        "plan": user.plan, # Adicionado para mostrar o plano atual
        "member_since": user.created_at.strftime('%d/%m/%Y')
    })

# --- ROTAS DE PAGAMENTO ---
@app.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('priceId')
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not price_id or price_id not in PRICE_ID_TO_CREDITS:
        return jsonify({'erro': 'ID do plano é inválido.'}), 400
    if not user:
        return jsonify({'erro': 'Utilizador não encontrado.'}), 404
    if not user.stripe_customer_id:
        return jsonify({'erro': 'Utilizador sem registo de pagamento. Contacte o suporte.'}), 500

    try:
        plan_info = PRICE_ID_TO_CREDITS[price_id]
        success_url = os.getenv("FRONTEND_URL") + "/dashboard?session_id={CHECKOUT_SESSION_ID}"
        cancel_url = os.getenv("FRONTEND_URL") + "/planos"
        
        # --- ALTERAÇÃO 3: LÓGICA DO MODO DE PAGAMENTO CORRIGIDA ---
        mode = 'subscription' if plan_info['type'] == 'plan' else 'payment'

        checkout_session = stripe.checkout.Session.create(
            line_items=[{'price': price_id, 'quantity': 1}],
            mode=mode,
            success_url=success_url,
            cancel_url=cancel_url,
            customer=user.stripe_customer_id, # Usa o ID do cliente, que é o correto
            metadata={
                'user_id': user.id,
                'price_id': price_id
            }
        )
        return jsonify({'url': checkout_session.url})

    except Exception as e:
        app.logger.error(f"Erro ao criar sessão no Stripe: {e}")
        return jsonify({'erro': str(e)}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, stripe_webhook_secret)
    except ValueError: return 'Payload inválido', 400
    except stripe.error.SignatureVerificationError: return 'Assinatura inválida', 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        price_id = session.get('metadata', {}).get('price_id')

        if not user_id or not price_id:
            app.logger.error("Webhook recebeu checkout.session.completed sem user_id ou price_id.")
            return 'Metadados em falta', 400
        
        user = User.query.get(int(user_id))
        plan_info = PRICE_ID_TO_CREDITS.get(price_id)
        
        if user and plan_info:
            # --- ALTERAÇÃO 4: LÓGICA DE ATUALIZAÇÃO DO USUÁRIO CORRIGIDA ---
            credits_to_add = plan_info.get('credits', 0)
            user.credits += credits_to_add
            
            # Se for um plano de assinatura, atualiza o nome do plano do usuário
            if plan_info.get('type') == 'plan':
                user.plan = plan_info.get('name', user.plan)
            
            db.session.commit()
            app.logger.info(f"Sucesso: {credits_to_add} créditos adicionados ao utilizador {user.email}. Plano atual: {user.plan}")
        else:
            app.logger.error(f"Webhook: Utilizador {user_id} ou Price ID {price_id} não encontrado.")
    
    return 'Sucesso', 200

# --- ROTA DE GERAÇÃO DE ÁUDIO (SEU CÓDIGO ORIGINAL, SEM ALTERAÇÕES) ---
def extrair_texto_de_pdf(arquivo_pdf_em_memoria):
    try:
        reader = PyPDF2.PdfReader(arquivo_pdf_em_memoria)
        texto_completo = ""
        for page in reader.pages:
            texto_completo += page.extract_text() or ""
        return texto_completo
    except Exception as e:
        print(f"Erro ao ler PDF: {e}")
        return None

def gerar_resumo_com_gemini(texto_completo):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"Você é um especialista em extrair a essência de um texto. Crie um roteiro para um resumo em áudio no formato de uma conversa entre dois apresentadores, 'Alex' e 'Bia', discutindo os pontos principais do seguinte texto. Seja dinâmico e envolvente. O texto é: '{texto_completo}'"
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Erro na chamada da API Gemini: {e}")
        return None

def gerar_audio_do_texto(texto_resumo):
    try:
        from google.cloud import texttospeech
        client = texttospeech.TextToSpeechClient()
        synthesis_input = texttospeech.SynthesisInput(text=texto_resumo)
        voice = texttospeech.VoiceSelectionParams(language_code="pt-BR", name="pt-BR-Wavenet-B")
        audio_config = texttospeech.AudioConfig(audio_encoding=texttospeech.AudioEncoding.MP3)
        response = client.synthesize_speech(input=synthesis_input, voice=voice, audio_config=audio_config)
        return response.audio_content
    except Exception as e:
        print(f"Erro ao gerar áudio: {e}")
        return None

@app.route('/gerar-audio', methods=['POST'])
@jwt_required()
def gerar_audio_endpoint():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user: return jsonify({"erro": "Usuário de autenticação inválido."}), 404
    if 'ebook_file' not in request.files: return jsonify({"erro": "Nenhum arquivo enviado com o nome esperado."}), 422
    arquivo = request.files['ebook_file']
    if arquivo.filename == '': return jsonify({"erro": "Nenhum arquivo selecionado."}), 400
    texto_extraido = extrair_texto_de_pdf(io.BytesIO(arquivo.read()))
    if not texto_extraido or len(texto_extraido) < 10: return jsonify({"erro": "Não foi possível extrair conteúdo válido do PDF."}), 400
    custo_em_creditos = (len(texto_extraido) // 15000) + 1
    if user.credits < custo_em_creditos: return jsonify({"erro": "Créditos insuficientes.", "seu_saldo": user.credits, "custo_necessario": custo_em_creditos}), 402
    resumo_texto = gerar_resumo_com_gemini(texto_extraido)
    if not resumo_texto: return jsonify({"erro": "Falha ao gerar resumo de texto."}), 500
    audio_mp3 = gerar_audio_do_texto(resumo_texto)
    if not audio_mp3: return jsonify({"erro": "Falha ao converter resumo em áudio."}), 500
    user.credits -= custo_em_creditos
    db.session.commit()
    return send_file(io.BytesIO(audio_mp3), mimetype='audio/mpeg', as_attachment=True, download_name='resumo_aihugg.mp3')

@app.route('/')
def home():
    return 'API AIHugg está online! 🚀'

# --- EXECUÇÃO PRINCIPAL (APENAS LOCAL) ---
if __name__ == '__main__':
    with app.app_context():
        # Este comando cria as tabelas se não existirem, incluindo as novas colunas
        db.create_all() 
    app.run(debug=True, port=5001)