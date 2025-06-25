# app.py - VERSÃO FINAL COM LOGS DE DEPURAÇÃO

import os
import io
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
# Configura o CORS para permitir requisições do seu frontend
CORS(app, resources={r"/*": {"origins": "*"}}) # Para testes, permite tudo. Depois podemos restringir.

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- FUNÇÕES AUXILIARES ---
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

# --- ROTAS DA APLICAÇÃO ---
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

if __name__ == '__main__':
    app.run(debug=True, port=5001)

