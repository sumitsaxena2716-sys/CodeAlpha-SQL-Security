import os
from contextlib import contextmanager

import mysql.connector
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


@contextmanager
def get_cursor(dictionary=False):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=dictionary)

    try:
        yield connection, cursor
    finally:
        cursor.close()
        connection.close()


def execute(query, params=None, commit=True):
    with get_cursor() as (connection, cursor):
        cursor.execute(query, params or ())

        if commit:
            connection.commit()

        return cursor.rowcount


def fetch_one(query, params=None):
    with get_cursor(dictionary=True) as (connection, cursor):
        cursor.execute(query, params or ())
        return cursor.fetchone()


def fetch_all(query, params=None):
    with get_cursor(dictionary=True) as (connection, cursor):
        cursor.execute(query, params or ())
        return cursor.fetchall()


def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(150) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        phone_encrypted TEXT,
        security_note_encrypted TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS security_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event_type VARCHAR(80) NOT NULL,
        username VARCHAR(100),
        status VARCHAR(30) NOT NULL
    );
    """

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        for statement in schema.split(";"):
            statement = statement.strip()

            if statement:
                cursor.execute(statement)

        connection.commit()
    finally:
        cursor.close()
        connection.close()