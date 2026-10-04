from database import get_db_connection

try:
    connection = get_db_connection()
    if connection.is_connected():
        print("MySQL connection successful!")
    connection.close()
except Exception as exc:
    print("Database connection failed:", exc)
