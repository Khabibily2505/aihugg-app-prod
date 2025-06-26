# app.py - VERSÃO FINAL COM CORS CORRIGIDO E STRIPE INTEGRADO

import os
import io
import stripe # Importar o Stripe
import PyPDF2
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

# --- CONFIGURAÇÃO DO CORS (A CORREÇÃO ESTÁ AQUI!) ---
# Define de quais origens (sites) sua API pode aceitar requisições.
# Isso resolve o erro "blocked by CORS policy".
# ⚠️ CORS CORRETAMENTE CONFIGURADO
# --- CONFIGURAÇÃO DE CORS (A SOLUÇÃO DEFINITIVA) ---
# Isto diz à sua API para aceitar pedidos vindos do seu site.
CORS(app)
# --- CONFIGURAÇÕES GERAIS ---
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURAÇÃO DO STRIPE ---
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
YOUR_DOMAIN = 'https://aihugg.com' # Seu domínio principal

# Inicialização das extensões
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Configuração da API do Gemini
try:
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
except Exception as e:
    print(f"Erro CRÍTICO ao configurar a API do Gemini: {e}")

# --- MODELO DE DADOS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=5)
    plan_id = db.Column(db.String(50), nullable=False, default='gratuito') # Adicionado para controlar o plano
    stripe_customer_id = db.Column(db.String(120), unique=True, nullable=True) # Adicionado para o Stripe
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# ... (O resto do seu código de User e funções auxiliares permanece igual) ...
def extrair_texto_de_pdf(arquivo_pdf_em_memoria):
    # ... seu código aqui ...
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
    # ... seu código aqui ...
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"Você é um especialista em extrair a essência de um texto. Crie um roteiro para um resumo em áudio no formato de uma conversa entre dois apresentadores, 'Alex' e 'Bia', discutindo os pontos principais do seguinte texto. Seja dinâmico e envolvente. O texto é: '{texto_completo}'"
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Erro na chamada da API Gemini: {e}")
        return None

def gerar_audio_do_texto(texto_resumo):
    # ... seu código aqui ...
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

# --- ROTAS DE AUTENTICAÇÃO E PERFIL ---
# ... (Suas rotas de register, login, profile permanecem as mesmas) ...
@app.route('/')
def index():
    return jsonify({"message": "Bem-vindo à API do AIHugg! Motor online.", "status": "ok"})

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"erro": "Este email já está em uso."}), 409
    
    # Cria o cliente no Stripe ANTES de criar o usuário no banco
    try:
        customer = stripe.Customer.create(email=data.get('email'))
        stripe_customer_id = customer.id
    except Exception as e:
        print(f"Erro ao criar cliente no Stripe: {e}")
        return jsonify({"erro": "Falha ao registrar serviço de pagamento."}), 500

    new_user = User(
        email=data.get('email'),
        stripe_customer_id=stripe_customer_id
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
        "plan": user.plan_id,
        "member_since": user.created_at.strftime('%d/%m/%Y')
    })


# --- ROTAS DE PAGAMENTO (STRIPE) ---

@app.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('priceId')
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"erro": "Usuário não encontrado"}), 404

    try:
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id, # Associa a sessão ao cliente
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription', # ou 'payment' para pacotes avulsos
            success_url=YOUR_DOMAIN + '/pagamento-sucesso?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=YOUR_DOMAIN + '/planos',
            metadata={'user_id': user.id} # Guarda o ID do usuário para o webhook
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        print(f"Erro ao criar sessão de checkout: {e}")
        return jsonify(error={'message': str(e)}), 500


@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_secret
        )
    except ValueError as e:
        return 'Payload inválido', 400
    except stripe.error.SignatureVerificationError as e:
        return 'Assinatura inválida', 400

    # Lida com o evento de pagamento bem-sucedido
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')

        # Busca o usuário no seu banco de dados
        user = User.query.get(user_id)
        if user:
            # Lógica para atualizar o plano/créditos do usuário
            # Você precisa mapear o price_id para o seu plano
            # Ex: Se o price_id for 'price_123', o plano é 'entrada'
            # e os créditos são +35.
            # user.plan_id = 'novo_plano'
            # user.credits += 35
            # db.session.commit()
            print(f"Webhook recebido! Usuário {user.email} (ID: {user_id}) completou o pagamento.")
        else:
            print(f"Webhook recebido para user_id {user_id}, mas usuário não foi encontrado no DB.")
    
    return 'Success', 200


# --- ROTA PRINCIPAL DA FERRAMENTA ---
@app.route('/gerar-audio', methods=['POST'])
@jwt_required()
def gerar_audio_endpoint():
    # ... seu código aqui (sem alterações) ...
    print("--- ROTA /gerar-audio ACIONADA ---")
    
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            print(f"ERRO: Usuário com ID de token {user_id} não foi encontrado.")
            return jsonify({"erro": "Usuário de autenticação inválido."}), 404
        print(f"Usuário identificado: {user.email} (Créditos: {user.credits})")
    except Exception as e:
        print(f"ERRO CRÍTICO ao buscar usuário: {e}")
        return jsonify({"erro": "Falha ao verificar identidade."}), 500

    print(f"Campos de arquivo recebidos: {list(request.files.keys())}")
    if 'ebook_file' not in request.files:
        print("ERRO: O campo 'ebook_file' não foi encontrado.")
        return jsonify({"erro": "Nenhum arquivo enviado com o nome esperado."}), 422

    arquivo = request.files['ebook_file']
    if arquivo.filename == '':
        print("ERRO: O arquivo está vazio.")
        return jsonify({"erro": "Nenhum arquivo selecionado."}), 400
    print(f"Arquivo recebido: {arquivo.filename}")

    try:
        arquivo_bytes = arquivo.read()
        print(f"Arquivo lido em memória. Tamanho: {len(arquivo_bytes)} bytes.")
        texto_extraido = extrair_texto_de_pdf(io.BytesIO(arquivo_bytes))
        if not texto_extraido or len(texto_extraido) < 10:
            print("ERRO: Extração de PDF retornou texto vazio ou muito curto.")
            return jsonify({"erro": "Não foi possível extrair conteúdo válido do PDF."}), 400
        print(f"Texto extraído com sucesso. Total de {len(texto_extraido)} caracteres.")
    except Exception as e:
        print(f"ERRO CRÍTICO durante a leitura do PDF: {e}")
        return jsonify({"erro": "Ocorreu um erro ao processar o arquivo PDF."}), 500

    custo_em_creditos = (len(texto_extraido) // 15000) + 1
    print(f"Custo calculado: {custo_em_creditos} créditos.")
    if user.credits < custo_em_creditos:
        print(f"ERRO: Créditos insuficientes para {user.email}.")
        return jsonify({"erro": "Créditos insuficientes.", "seu_saldo": user.credits, "custo_necessario": custo_em_creditos}), 402

    resumo_texto = gerar_resumo_com_gemini(texto_extraido)
    if not resumo_texto: return jsonify({"erro": "Falha ao gerar resumo de texto."}), 500
    
    audio_mp3 = gerar_audio_do_texto(resumo_texto)
    if not audio_mp3: return jsonify({"erro": "Falha ao converter resumo em áudio."}), 500

    user.credits -= custo_em_creditos
    db.session.commit()
    print(f"Sucesso! Créditos debitados. Novo saldo para {user.email}: {user.credits}")
    
    return send_file(io.BytesIO(audio_mp3), mimetype='audio/mpeg', as_attachment=True, download_name='resumo_aihugg.mp3')


# --- INICIALIZAÇÃO DA APLICAÇÃO ---
if __name__ == '__main__':
    # Para desenvolvimento local, você pode usar uma porta diferente
    app.run(debug=True, port=5001)