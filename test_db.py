"""Check MySQL connectivity using the current .env configuration."""
import sys

from database import get_db_connection


def main():
    connection = None
    try:
        connection = get_db_connection()
        print("Database connection: SUCCESS")
        print("Database:", connection.database)
        return 0
    except Exception as exc:
        print("Database connection: FAILED")
        print(f"Reason: {exc.__class__.__name__}: {exc}")
        print("Check that MySQL is running, schema.sql has been executed, and .env credentials are correct.")
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())
