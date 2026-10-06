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
    )


@contextmanager
def cursor(dictionary=False):
    connection = get_db_connection()
    cur = connection.cursor(dictionary=dictionary)
    try:
        yield connection, cur
    finally:
        cur.close()
        connection.close()


def fetch_one(query, params=(), dictionary=False):
    with cursor(dictionary=dictionary) as (_, cur):
        cur.execute(query, params)
        return cur.fetchone()


def fetch_all(query, params=(), dictionary=False):
    with cursor(dictionary=dictionary) as (_, cur):
        cur.execute(query, params)
        return cur.fetchall()


def execute(query, params=(), commit=False):
    with cursor() as (connection, cur):
        cur.execute(query, params)
        if commit:
            connection.commit()
        return cur.rowcount


def init_db():
    connection = get_db_connection()
    cur = connection.cursor()
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(150) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                phone_encrypted TEXT,
                security_note_encrypted TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type VARCHAR(80) NOT NULL,
                username VARCHAR(100),
                status VARCHAR(30) NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        cur.close()
        connection.close()
