from database import get_db_connection

connection = get_db_connection()
try:
    print("Database connection: SUCCESS")
    print("Database:", connection.database)
finally:
    connection.close()
