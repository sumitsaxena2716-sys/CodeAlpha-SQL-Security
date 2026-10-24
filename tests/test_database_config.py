"""Database connector configuration regression tests."""
import unittest
from unittest.mock import patch

import database


class DatabaseConfigurationTests(unittest.TestCase):
    @patch("database.mysql.connector.connect")
    def test_uses_pure_python_connector_and_timeout(self, connect):
        database.get_db_connection()
        kwargs = connect.call_args.kwargs
        self.assertIs(kwargs["use_pure"], True)
        self.assertEqual(kwargs["connection_timeout"], 5)


if __name__ == "__main__":
    unittest.main()
