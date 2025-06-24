import os
from dotenv import load_dotenv
import psycopg2

load_dotenv()  # Carrega as variáveis do .env

DATABASE_URL = os.getenv('DATABASE_URL')
print("DATABASE_URL:", DATABASE_URL)  # Para conferir

try:
    conn = psycopg2.connect(DATABASE_URL)
    print("Conectou com sucesso!")
    conn.close()
except Exception as e:
    print("Erro ao conectar no banco:", e)
