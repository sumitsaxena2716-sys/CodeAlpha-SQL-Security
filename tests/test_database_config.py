"""Database connection and operation regression tests."""

import os
import unittest
from unittest.mock import MagicMock, patch

import database


class DatabaseConfigurationTests(unittest.TestCase):

    @patch("database.mysql.connector.connect")
    @patch.dict(
        os.environ,
        {
            "DB_HOST": "test-host",
            "DB_PORT": "3307",
            "DB_USER": "test-user",
            "DB_PASSWORD": "test-password",
            "DB_NAME": "test-database",
        },
    )
    def test_uses_environment_database_configuration(self, connect):
        database.get_db_connection()

        connect.assert_called_once_with(
            host="test-host",
            port=3307,
            user="test-user",
            password="test-password",
            database="test-database",
            use_pure=True,
            connection_timeout=5,
        )

    @patch("database.mysql.connector.connect")
    def test_uses_default_database_configuration(self, connect):
        env_names = ("DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME")
        with patch.dict(os.environ, {}, clear=True):
            database.get_db_connection()

        kwargs = connect.call_args.kwargs
        self.assertEqual(kwargs["host"], "127.0.0.1")
        self.assertEqual(kwargs["port"], 3306)
        self.assertEqual(kwargs["user"], "root")
        self.assertEqual(kwargs["password"], "")
        self.assertEqual(kwargs["database"], "codealpha_security")
        self.assertTrue(kwargs["use_pure"])
        self.assertEqual(kwargs["connection_timeout"], 5)

    @patch("database.get_db_connection")
    def test_get_cursor_closes_cursor_and_connection(self, get_connection):
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value = cursor
        get_connection.return_value = connection

        with database.get_cursor(dictionary=True) as (conn, cur):
            self.assertIs(conn, connection)
            self.assertIs(cur, cursor)

        connection.cursor.assert_called_once_with(dictionary=True)
        cursor.close.assert_called_once()
        connection.close.assert_called_once()

    @patch("database.get_db_connection")
    def test_get_cursor_closes_connection_if_cursor_creation_fails(
        self, get_connection
    ):
        connection = MagicMock()
        connection.cursor.side_effect = RuntimeError("cursor failure")
        get_connection.return_value = connection

        with self.assertRaisesRegex(RuntimeError, "cursor failure"):
            with database.get_cursor():
                pass

        connection.close.assert_called_once()

    @patch("database.get_cursor")
    def test_execute_runs_query_and_commits(self, get_cursor):
        connection = MagicMock()
        cursor = MagicMock()
        get_cursor.return_value.__enter__.return_value = (connection, cursor)
        cursor.rowcount = 3

        result = database.execute(
            "UPDATE users SET status = %s WHERE id = %s",
            ("active", 10),
        )

        cursor.execute.assert_called_once_with(
            "UPDATE users SET status = %s WHERE id = %s",
            ("active", 10),
        )
        connection.commit.assert_called_once()
        self.assertEqual(result, 3)

    @patch("database.get_cursor")
    def test_execute_can_skip_commit(self, get_cursor):
        connection = MagicMock()
        cursor = MagicMock()
        get_cursor.return_value.__enter__.return_value = (connection, cursor)
        cursor.rowcount = 1

        result = database.execute("DELETE FROM users", commit=False)

        cursor.execute.assert_called_once_with("DELETE FROM users", ())
        connection.commit.assert_not_called()
        self.assertEqual(result, 1)

    @patch("database.get_cursor")
    def test_fetch_one_returns_single_row(self, get_cursor):
        connection = MagicMock()
        cursor = MagicMock()
        expected = {"id": 1, "username": "alice"}
        cursor.fetchone.return_value = expected
        get_cursor.return_value.__enter__.return_value = (connection, cursor)

        result = database.fetch_one("SELECT * FROM users WHERE id = %s", (1,))

        get_cursor.assert_called_once_with(dictionary=True)
        cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE id = %s", (1,)
        )
        self.assertEqual(result, expected)

    @patch("database.get_cursor")
    def test_fetch_all_returns_rows(self, get_cursor):
        connection = MagicMock()
        cursor = MagicMock()
        expected = [
            {"id": 1, "username": "alice"},
            {"id": 2, "username": "bob"},
        ]
        cursor.fetchall.return_value = expected
        get_cursor.return_value.__enter__.return_value = (connection, cursor)

        result = database.fetch_all("SELECT * FROM users")

        get_cursor.assert_called_once_with(dictionary=True)
        cursor.execute.assert_called_once_with("SELECT * FROM users", ())
        self.assertEqual(result, expected)

    @patch("database.get_db_connection")
    def test_init_db_creates_tables_and_commits(self, get_connection):
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value = cursor
        get_connection.return_value = connection

        database.init_db()

        self.assertEqual(cursor.execute.call_count, 2)
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS users", cursor.execute.call_args_list[0].args[0]
        )
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS security_events",
            cursor.execute.call_args_list[1].args[0],
        )
        connection.commit.assert_called_once()
        connection.rollback.assert_not_called()
        cursor.close.assert_called_once()
        connection.close.assert_called_once()

    @patch("database.get_db_connection")
    def test_init_db_rolls_back_and_reraises_database_error(self, get_connection):
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value = cursor
        cursor.execute.side_effect = RuntimeError("database failure")
        get_connection.return_value = connection

        with self.assertRaisesRegex(RuntimeError, "database failure"):
            database.init_db()

        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()
        cursor.close.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
