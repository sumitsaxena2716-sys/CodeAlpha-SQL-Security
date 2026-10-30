"""Unit tests for the local, in-memory login throttling helper."""

import unittest
from unittest.mock import patch

import app as cipher_app


class LoginThrottleTests(unittest.TestCase):
    def setUp(self):
        cipher_app.LOGIN_BUCKET.clear()

    def test_five_failed_attempts_lock_account(self):
        for _ in range(cipher_app.MAX_LOGIN_ATTEMPTS):
            cipher_app.record_failed_login("TestUser")
        self.assertTrue(cipher_app.is_locked("testuser"))

    def test_username_case_and_whitespace_share_bucket(self):
        cipher_app.record_failed_login(" TestUser ")
        self.assertEqual(cipher_app.LOGIN_BUCKET["testuser"]["attempts"], 1)

    def test_successful_login_clears_bucket(self):
        cipher_app.record_failed_login("testuser")
        cipher_app.clear_login_attempts(" TESTUSER ")
        self.assertNotIn("testuser", cipher_app.LOGIN_BUCKET)

    def test_lock_expires(self):
        with patch.object(cipher_app.time, "time", return_value=1000):
            for _ in range(cipher_app.MAX_LOGIN_ATTEMPTS):
                cipher_app.record_failed_login("testuser")
        with patch.object(
            cipher_app.time, "time", return_value=1000 + cipher_app.LOCKOUT_SECONDS + 1
        ):
            self.assertFalse(cipher_app.is_locked("testuser"))
        self.assertNotIn("testuser", cipher_app.LOGIN_BUCKET)


if __name__ == "__main__":
    unittest.main()
