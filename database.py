import os
import mysql.connector
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "codealpha_security"),
        ssl_ca=os.getenv("DB_SSL_CA", "tidb-ca.pem"),
        ssl_verify_cert=True,
        ssl_verify_identity=True,
    )