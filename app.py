# app.py - VERSÃO MESTRE E DEFINITIVA

import os
from flask import Flask, jsonify
from dotenv import load_dotenv
import google.generativeai as genai

# Carrega as variáveis de ambiente do arquivo .env para uso local
load_dotenv()

# A variável 'app' que a Vercel PROCURA E PRECISA encontrar
app = Flask(__name__)

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