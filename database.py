import os
from contextlib import contextmanager

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """Create a MySQL connection using values from the local environment."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "codealpha_security"),
        # Avoid the native C-extension path, which can crash on some Windows/Python builds.
        use_pure=True,
        connection_timeout=5,
    )


@contextmanager
def get_cursor(dictionary=False):
    """Yield a cursor and connection, and always close both safely."""
    connection = get_db_connection()
    cursor = None
    try:
        cursor = connection.cursor(dictionary=dictionary)
        yield connection, cursor
    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


def execute(query, params=None, commit=True):
    """Execute a parameterized query and optionally commit changes."""
    with get_cursor() as (connection, cursor):
        cursor.execute(query, params or ())
        if commit:
            connection.commit()
        return cursor.rowcount


def fetch_one(query, params=None):
    """Fetch one row as a dictionary so templates can use named columns."""
    with get_cursor(dictionary=True) as (_connection, cursor):
        cursor.execute(query, params or ())
        return cursor.fetchone()


def fetch_all(query, params=None):
    """Fetch all rows as dictionaries so templates can use named columns."""
    with get_cursor(dictionary=True) as (_connection, cursor):
        cursor.execute(query, params or ())
        return cursor.fetchall()


def init_db():
    """Create the app's required tables if they do not already exist."""
    statements = [
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
        """,
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type VARCHAR(80) NOT NULL,
            username VARCHAR(100),
            status VARCHAR(30) NOT NULL
        )
        """,
    ]
    connection = get_db_connection()
    cursor = None
    try:
        cursor = connection.cursor()
        for statement in statements:
            cursor.execute(statement)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        if cursor is not None:
            cursor.close()
        connection.close()
