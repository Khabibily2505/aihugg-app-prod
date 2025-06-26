# app.py - VERSÃO FINAL COM PAGAMENTOS STRIPE

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
import stripe # Importa a biblioteca do Stripe

# Carrega as variáveis de ambiente do .env
load_dotenv()

# --- CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURAÇÃO DO STRIPE ---
stripe.api_key = os.getenv('STRIPE_API_SECRET_KEY')
stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET') # Vamos adicionar esta variável ao .env depois

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
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=5) # Créditos gratuitos iniciais
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# Mapeamento de Price IDs para a quantidade de créditos correspondente
# IMPORTANTE: Mantenha isto atualizado com os seus produtos no Stripe!
PRICE_ID_TO_CREDITS = {
      # --- Planos de Assinatura Mensal ---
    "price_1ReHqmF4Pfx9Nag9Srxn2ptJ": {"type": "plan", "name": "Entrada", "credits": 35},
    "price_1ReHrOF4Pfx9Nag98bnQTNDz": {"type": "plan", "name": "Iniciante", "credits": 15}, #+bônus
    "price_1ReHs1F4Pfx9Nag9o95BatBV": {"type": "plan", "name": "Leitor", "credits": 40},
    "price_1ReHsdF4Pfx9Nag9CrogYmaN": {"type": "plan", "name": "Criador", "credits": 80},
    "price_1ReHtOF4Pfx9Nag9Z2kRM9H2": {"type": "plan", "name": "Império", "credits": 150},
    # --- Pacotes de Créditos Avulsos ---
    "price_1ReHuGF4Pfx9Nag9LYN2cJhA": {"type": "credits", "name": "Recarga Rápida", "credits": 15},
    "price_1ReHvHF4Pfx9Nag9eOmQEvHK": {"type": "credits", "name": "Recarga Padrão", "credits": 30},
    "price_1ReHvwF4Pfx9Nag95iQRpo1L": {"type": "credits", "name": "Recarga Essencial", "credits": 70},
    "price_1ReHwZF4Pfx9Nag94G2eQua6": {"type": "credits", "name": "Recarga Inteligente", "credits": 100},
    "price_1ReHxMF4Pfx9Nag9A6XhifA8": {"type": "credits", "name": "Recarga Avançada", "credits": 150},
    "price_1ReHynF4Pfx9Nag941RzJPN2": {"type": "credits", "name": "Recarga Profissional", "credits": 250},

}

# --- ROTAS DE AUTENTICAÇÃO E PERFIL (sem alterações) ---
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
    return jsonify({"email": user.email, "credits": user.credits, "member_since": user.created_at.strftime('%d/%m/%Y')})


# --- NOVAS ROTAS DE PAGAMENTO ---

@app.route('/create-checkout-session', methods=['POST'])
@jwt_required() # Garante que apenas utilizadores logados podem comprar
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('priceId')
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not price_id:
        return jsonify({'erro': 'Price ID é obrigatório.'}), 400
    if not user:
        return jsonify({'erro': 'Utilizador não encontrado.'}), 404

    try:
        # URL's para onde o cliente será redirecionado após a compra
        success_url = "https://aihugg.com/dashboard?session_id={CHECKOUT_SESSION_ID}" # Pode ser uma página de sucesso
        cancel_url = "https://aihugg.com/planos" # Volta para a página de planos se cancelar

        checkout_session = stripe.checkout.Session.create(
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription' if price_id.startswith('price_') else 'payment', # 'subscription' para planos, 'payment' para avulsos
            success_url=success_url,
            cancel_url=cancel_url,
            # Passa o email do cliente para o Stripe e o ID do nosso user nos metadados
            customer_email=user.email,
            metadata={
                'user_id': user.id,
                'price_id': price_id
            }
        )
        # Retorna a URL da sessão de checkout para o frontend
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
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_secret
        )
    except ValueError as e:
        # Payload inválido
        return 'Payload inválido', 400
    except stripe.error.SignatureVerificationError as e:
        # Assinatura inválida
        return 'Assinatura inválida', 400

    # Processa o evento de checkout completo
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        price_id = session.get('metadata', {}).get('price_id')

        if not user_id or not price_id:
            app.logger.error("Webhook recebeu checkout.session.completed sem user_id ou price_id nos metadados.")
            return 'Metadados em falta', 400
        
        # Procura o utilizador no banco de dados
        user = User.query.get(user_id)
        if user:
            # Encontra a quantidade de créditos correspondente ao preço
            credits_to_add = PRICE_ID_TO_CREDITS.get(price_id)
            if credits_to_add:
                user.credits += credits_to_add
                db.session.commit()
                app.logger.info(f"Sucesso: {credits_to_add} créditos adicionados ao utilizador {user.email}.")
            else:
                app.logger.warning(f"Webhook: Price ID {price_id} não encontrado no mapeamento PRICE_ID_TO_CREDITS.")
        else:
            app.logger.error(f"Webhook: Utilizador com ID {user_id} não encontrado no banco de dados.")

    # Adicione outros tipos de eventos aqui se precisar (ex: renovação de assinatura)
    
    return 'Sucesso', 200
# --- ROTA DE GERAÇÃO DE ÁUDIO (sem alterações) ---
# ... (mantenha aqui a sua rota /gerar-audio e as funções auxiliares) ...
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


# --- EXECUÇÃO PRINCIPAL ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)