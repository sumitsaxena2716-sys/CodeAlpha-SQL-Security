"""Flask route and security regression tests; database operations are mocked."""

import os
import unittest
from unittest.mock import MagicMock, patch

from werkzeug.security import generate_password_hash

import app as cipher_app


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        cipher_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key-for-unit-tests-only",
        )
        cipher_app.LOGIN_BUCKET.clear()
        self.client = cipher_app.app.test_client()

    def _csrf(self, path="/login"):
        response = self.client.get(path)
        response.close()
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def test_public_pages_render(self):
        for path in (
            "/",
            "/login",
            "/register",
            "/security-demo",
            "/privacy",
            "/terms",
            "/robots.txt",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_security_demo_input_has_associated_label(self):
        response = self.client.get("/security-demo")
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'<label for="sample">', response.data)
            self.assertIn(b'id="sample"', response.data)
        finally:
            response.close()

    def test_get_only_routes_reject_post(self):
        for path in (
            "/",
            "/dashboard",
            "/security-demo",
            "/security-center",
            "/privacy",
            "/terms",
            "/robots.txt",
            "/sitemap.xml",
        ):
            with self.subTest(path=path):
                response = self.client.post(path)
                self.assertEqual(response.status_code, 405)
                response.close()

    def test_missing_and_invalid_csrf_are_rejected(self):
        missing = self.client.post(
            "/login", data={"username": "tester", "password": "wrong"}
        )
        self.assertEqual(missing.status_code, 400)
        missing.close()

        token = self._csrf()
        invalid = self.client.post(
            "/login",
            data={"csrf_token": "invalid", "username": "tester", "password": "wrong"},
        )
        self.assertEqual(invalid.status_code, 400)
        invalid.close()

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers["Location"])
        response.close()

    def test_custom_404_and_security_headers(self):
        response = self.client.get("/route-that-does-not-exist")
        try:
            self.assertEqual(response.status_code, 404)
            self.assertIn(b"Return home", response.data)
            self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
            self.assertIn("Content-Security-Policy", response.headers)
            self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        finally:
            response.close()

    def test_favicon_and_robots_available(self):
        for path in ("/static/favicon.svg", "/robots.txt"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_login_uses_parameterized_lookup(self):
        token = self._csrf()
        with patch.object(
            cipher_app, "fetch_one", return_value=None
        ) as fetch, patch.object(cipher_app, "record_event"):
            response = self.client.post(
                "/login",
                data={"csrf_token": token, "username": "tester", "password": "wrong"},
            )
        try:
            self.assertEqual(response.status_code, 200)
            fetch.assert_called_once()
            self.assertIn("WHERE username = %s", fetch.call_args.args[0])
            self.assertEqual(fetch.call_args.args[1], ("tester",))
        finally:
            response.close()

    def test_sql_injection_lab_treats_payload_as_plain_parameter(self):
        token = self._csrf("/security-demo")
        payload = "' OR '1'='1"
        with patch.object(
            cipher_app, "fetch_one", return_value={"user_count": 0}
        ) as fetch:
            response = self.client.post(
                "/security-demo/test",
                data={"csrf_token": token, "sample": payload},
            )
        try:
            self.assertEqual(response.status_code, 200)
            fetch.assert_called_once()
            self.assertIn("WHERE username = %s", fetch.call_args.args[0])
            self.assertEqual(fetch.call_args.args[1], (payload,))
            self.assertIn(b"Matching users: 0", response.data)
        finally:
            response.close()

    def test_sql_injection_lab_rejects_missing_csrf(self):
        response = self.client.post(
            "/security-demo/test", data={"sample": "' OR '1'='1"}
        )
        self.assertEqual(response.status_code, 400)
        response.close()

    def test_security_center_only_queries_current_user_events(self):
        with self.client.session_transaction() as sess:
            sess.update(user_id=10, username="alice", csrf_token="test-csrf")
        with patch.object(
            cipher_app, "get_current_user", return_value={"username": "alice"}
        ), patch.object(cipher_app, "fetch_all", return_value=[]) as fetch:
            response = self.client.get("/security-center")
        try:
            self.assertEqual(response.status_code, 200)
            fetch.assert_called_once()
            self.assertIn("WHERE username = %s", fetch.call_args.args[0])
            self.assertEqual(fetch.call_args.args[1], ("alice",))
        finally:
            response.close()

    def test_registration_validation_rejects_invalid_email(self):
        self.assertEqual(
            cipher_app._registration_validation_error(
                "bad-email", "password123", "", ""
            ),
            "Enter a valid email address.",
        )

    def test_registration_validation_rejects_invalid_phone(self):
        self.assertIn(
            "phone",
            cipher_app._registration_validation_error(
                "user@example.com", "password123", "not-a-phone", ""
            ).lower(),
        )

    def test_registration_validation_accepts_valid_fields(self):
        self.assertIsNone(
            cipher_app._registration_validation_error(
                "user@example.com", "password123", "+91 98765 43210", "test note"
            )
        )

    def test_registration_invalid_phone_returns_validation_response(self):
        token = self._csrf("/register")
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "tester",
                "email": "tester@example.com",
                "password": "password123",
                "phone": "invalid-phone",
            },
        )
        try:
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"Enter a valid phone number", response.data)
        finally:
            response.close()


class AppCoverageTests(unittest.TestCase):
    """Exercise application branches with database calls isolated by mocks."""

    def setUp(self):
        cipher_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key-for-unit-tests-only",
            MAX_CONTENT_LENGTH=1024 * 1024,
        )
        cipher_app.LOGIN_BUCKET.clear()
        self.client = cipher_app.app.test_client()

    def csrf(self, path="/login"):
        response = self.client.get(path)
        if response.status_code != 200:
            response.close()
            response = self.client.get("/login")
        response.close()
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def post_data(self, path, data):
        data = dict(data)
        data["csrf_token"] = self.csrf(path)
        return self.client.post(path, data=data)

    def test_aes_key_loader_handles_missing_invalid_and_valid_keys(self):
        import base64

        with patch.dict(os.environ, {"AES_256_KEY": ""}, clear=False):
            self.assertIsNone(cipher_app._load_aes_key())
        with patch.dict(os.environ, {"AES_256_KEY": "not-base64!"}, clear=False):
            self.assertIsNone(cipher_app._load_aes_key())
        valid = base64.urlsafe_b64encode(b"k" * 32).decode("ascii")
        with patch.dict(os.environ, {"AES_256_KEY": valid}, clear=False):
            self.assertEqual(cipher_app._load_aes_key(), b"k" * 32)
        short = base64.urlsafe_b64encode(b"short").decode("ascii")
        with patch.dict(os.environ, {"AES_256_KEY": short}, clear=False):
            self.assertIsNone(cipher_app._load_aes_key())

    def test_encrypt_decrypt_round_trip_and_empty_values(self):
        with patch.object(cipher_app, "AES_KEY", b"k" * 32):
            self.assertEqual(cipher_app.encrypt_sensitive(""), "")
            self.assertEqual(cipher_app.decrypt_sensitive(""), "")
            token = cipher_app.encrypt_sensitive("private information")
            self.assertNotEqual(token, "private information")
            self.assertEqual(cipher_app.decrypt_sensitive(token), "private information")

    def test_encryption_requires_a_valid_key_and_decryption_fails_closed(self):
        with patch.object(cipher_app, "AES_KEY", None):
            with self.assertRaisesRegex(RuntimeError, "AES_256_KEY"):
                cipher_app.encrypt_sensitive("private")
            self.assertEqual(cipher_app.decrypt_sensitive("ciphertext"), "")
        with patch.object(cipher_app, "AES_KEY", b"k" * 32):
            self.assertEqual(
                cipher_app.decrypt_sensitive("not-valid-token"), "[encrypted]"
            )
            token = cipher_app.encrypt_sensitive("secret")
            tampered = ("A" if token[0] != "A" else "B") + token[1:]
            self.assertEqual(cipher_app.decrypt_sensitive(tampered), "[encrypted]")

    def test_csrf_token_is_stable_within_session(self):
        with self.client:
            self.client.get("/login")
            first = cipher_app.csrf_token()
            second = cipher_app.csrf_token()
            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first), 32)

    def test_site_metadata_context_processor(self):
        with patch.dict(os.environ, {"APP_BASE_URL": "https://example.test///"}):
            metadata = cipher_app.inject_site_metadata()
        self.assertEqual(metadata["app_base_url"], "https://example.test")
        self.assertIsInstance(metadata["current_year"], int)

    def test_security_headers_include_hsts_for_https(self):
        with cipher_app.app.test_request_context("/", base_url="https://example.test"):
            response = cipher_app.app.response_class("ok")
            secured = cipher_app.security_headers(response)
        self.assertIn("max-age=31536000", secured.headers["Strict-Transport-Security"])
        self.assertEqual(
            secured.headers["Referrer-Policy"], "strict-origin-when-cross-origin"
        )
        self.assertIn("geolocation=()", secured.headers["Permissions-Policy"])

    def test_security_event_write_failure_is_logged_and_suppressed(self):
        with patch.object(
            cipher_app, "execute", side_effect=RuntimeError("database unavailable")
        ), patch.object(cipher_app.logging, "exception") as log_exception:
            cipher_app.record_event("LOGIN", "alice", "FAILED")
        log_exception.assert_called_once()

    def test_current_user_returns_none_without_session(self):
        with self.client:
            self.client.get("/")
            self.assertIsNone(cipher_app.get_current_user())

    def test_current_user_fetches_and_decrypts_private_fields(self):
        user = {
            "id": 7,
            "username": "alice",
            "phone_encrypted": "encrypted-phone",
            "security_note_encrypted": "encrypted-note",
        }

        with self.client:
            with self.client.session_transaction() as sess:
                sess["user_id"] = 7

            self.client.get("/")

            with patch.object(
                cipher_app, "fetch_one", return_value=user
            ) as fetch, patch.object(
                cipher_app,
                "decrypt_sensitive",
                side_effect=["9876543210", "private note"],
            ):
                current = cipher_app.get_current_user()

        self.assertEqual(current["phone"], "9876543210")
        self.assertEqual(current["security_note"], "private note")
        self.assertEqual(fetch.call_args.args[1], (7,))

    def test_current_user_returns_none_when_database_user_missing(self):
        with self.client:
            with self.client.session_transaction() as sess:
                sess["user_id"] = 999

            self.client.get("/")

            with patch.object(cipher_app, "fetch_one", return_value=None):
                self.assertIsNone(cipher_app.get_current_user())

    def test_registration_rejects_short_password_long_note_and_long_email(self):
        cases = [
            ("user@example.com", "short", "", ""),
            ("user@example.com", "password123", "", "x" * 501),
            ("a" * 145 + "@example.com", "password123", "", ""),
        ]
        for email, password, phone, note in cases:
            with self.subTest(
                email_length=len(email),
                password_length=len(password),
                note_length=len(note),
            ):
                message = cipher_app._registration_validation_error(
                    email, password, phone, note
                )
                self.assertIsNotNone(message)

    def test_registration_get_renders_form(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_registration_without_aes_key_does_not_touch_database(self):
        response = self.post_data(
            "/register",
            {
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "phone": "",
                "security_note": "",
            },
        )
        with patch.object(cipher_app, "AES_KEY", None), patch.object(
            cipher_app, "get_cursor"
        ) as get_cursor:
            # Re-submit with a fresh CSRF token after the first request setup.
            response.close()
            response = self.post_data(
                "/register",
                {
                    "username": "alice",
                    "email": "alice@example.com",
                    "password": "password123",
                    "phone": "",
                    "security_note": "",
                },
            )
            self.assertEqual(response.status_code, 200)
            get_cursor.assert_not_called()
        response.close()

    def test_registration_success_hashes_password_encrypts_fields_and_redirects(self):
        connection = MagicMock()
        cursor = MagicMock()
        get_cursor = MagicMock()
        get_cursor.return_value.__enter__.return_value = (connection, cursor)
        with patch.object(cipher_app, "AES_KEY", b"k" * 32), patch.object(
            cipher_app, "get_cursor", get_cursor
        ), patch.object(cipher_app, "record_event") as record_event:
            response = self.post_data(
                "/register",
                {
                    "username": "alice",
                    "email": "alice@example.com",
                    "password": "password123",
                    "phone": "9876543210",
                    "security_note": "private note",
                },
            )
        try:
            self.assertEqual(response.status_code, 302)
            self.assertIn("/login", response.headers["Location"])
            sql, params = cursor.execute.call_args.args
            self.assertIn("INSERT INTO users", sql)
            self.assertEqual(params[0], "alice")
            self.assertEqual(params[1], "alice@example.com")
            self.assertNotEqual(params[2], "password123")
            self.assertNotEqual(params[3], "9876543210")
            record_event.assert_called_once_with("REGISTRATION", "alice", "SUCCESS")
            connection.commit.assert_called_once()
        finally:
            response.close()

    def test_registration_database_failure_is_handled(self):
        manager = MagicMock()
        manager.__enter__.side_effect = RuntimeError("duplicate user")
        with patch.object(cipher_app, "AES_KEY", b"k" * 32), patch.object(
            cipher_app, "get_cursor", return_value=manager
        ), patch.object(cipher_app, "record_event") as record_event:
            response = self.post_data(
                "/register",
                {
                    "username": "alice",
                    "email": "alice@example.com",
                    "password": "password123",
                    "phone": "",
                    "security_note": "",
                },
            )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Registration failed", response.data)
            record_event.assert_called_once_with("REGISTRATION", "alice", "FAILED")
        finally:
            response.close()

    def test_login_get_renders_form(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_locked_login_does_not_query_database(self):
        with patch.object(cipher_app, "is_locked", return_value=True), patch.object(
            cipher_app, "fetch_one"
        ) as fetch:
            response = self.post_data(
                "/login",
                {
                    "username": "alice",
                    "password": "password123",
                },
            )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Too many failed attempts", response.data)
            fetch.assert_not_called()
        finally:
            response.close()

    def test_successful_login_sets_session_and_redirects(self):
        user = {
            "id": 7,
            "username": "alice",
            "password_hash": generate_password_hash("password123"),
        }
        with patch.object(cipher_app, "fetch_one", return_value=user), patch.object(
            cipher_app, "record_event"
        ) as record_event:
            response = self.post_data(
                "/login",
                {
                    "username": "alice",
                    "password": "password123",
                },
            )
        try:
            self.assertEqual(response.status_code, 302)
            self.assertIn("/dashboard", response.headers["Location"])
            with self.client.session_transaction() as sess:
                self.assertEqual(sess["user_id"], 7)
                self.assertEqual(sess["username"], "alice")
                self.assertTrue(sess.get("csrf_token"))
            record_event.assert_called_once_with("LOGIN", "alice", "SUCCESS")
        finally:
            response.close()

    def test_failed_login_records_attempt_and_event(self):
        with patch.object(cipher_app, "fetch_one", return_value=None), patch.object(
            cipher_app, "record_event"
        ) as record_event, patch.object(cipher_app, "record_failed_login") as failed:
            response = self.post_data(
                "/login",
                {
                    "username": "alice",
                    "password": "wrong-password",
                },
            )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Invalid username or password", response.data)
            failed.assert_called_once_with("alice")
            record_event.assert_called_once_with("LOGIN", "alice", "FAILED")
        finally:
            response.close()

    def test_login_database_exception_is_handled(self):
        with patch.object(
            cipher_app, "fetch_one", side_effect=RuntimeError("db down")
        ), patch.object(cipher_app, "record_event") as record_event:
            response = self.post_data(
                "/login",
                {
                    "username": "alice",
                    "password": "password123",
                },
            )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Unable to process login", response.data)
            record_event.assert_called_once_with("LOGIN", "alice", "ERROR")
        finally:
            response.close()

    def test_profile_requires_login(self):
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers["Location"])
        response.close()

    def test_profile_invalid_phone_and_long_note_are_rejected(self):
        with self.client.session_transaction() as sess:
            sess.update(user_id=7, username="alice")
        with patch.object(
            cipher_app, "get_current_user", return_value={"username": "alice"}
        ):
            bad_phone = self.post_data(
                "/profile", {"phone": "abc", "security_note": ""}
            )
            self.assertEqual(bad_phone.status_code, 400)
            bad_phone.close()
            long_note = self.post_data(
                "/profile", {"phone": "", "security_note": "x" * 501}
            )
            self.assertEqual(long_note.status_code, 400)
            long_note.close()

    def test_profile_success_updates_encrypted_fields(self):
        with self.client.session_transaction() as sess:
            sess.update(user_id=7, username="alice")
        with patch.object(
            cipher_app, "get_current_user", return_value={"username": "alice"}
        ), patch.object(
            cipher_app,
            "encrypt_sensitive",
            side_effect=["encrypted-phone", "encrypted-note"],
        ), patch.object(
            cipher_app, "execute"
        ) as execute, patch.object(
            cipher_app, "record_event"
        ) as record_event:
            response = self.post_data(
                "/profile", {"phone": "9876543210", "security_note": "private"}
            )
        try:
            self.assertEqual(response.status_code, 302)
            self.assertIn("/profile", response.headers["Location"])
            self.assertEqual(
                execute.call_args.args[1],
                ("encrypted-phone", "encrypted-note", 7),
            )
            record_event.assert_called_once_with(
                "PROFILE_ENCRYPTED_UPDATE", "alice", "SUCCESS"
            )
        finally:
            response.close()

    def test_profile_database_failure_is_handled(self):
        with self.client.session_transaction() as sess:
            sess.update(user_id=7, username="alice")
        with patch.object(
            cipher_app, "get_current_user", return_value={"username": "alice"}
        ), patch.object(
            cipher_app, "encrypt_sensitive", return_value="encrypted"
        ), patch.object(
            cipher_app, "execute", side_effect=RuntimeError("db down")
        ):
            response = self.post_data(
                "/profile", {"phone": "", "security_note": "private"}
            )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Profile could not be updated", response.data)
        finally:
            response.close()

    def test_logout_clears_session_and_records_event(self):
        with self.client.session_transaction() as sess:
            sess.update(user_id=7, username="alice")
        with patch.object(cipher_app, "record_event") as record_event:
            response = self.post_data("/logout", {})
        try:
            self.assertEqual(response.status_code, 302)
            with self.client.session_transaction() as sess:
                self.assertNotIn("user_id", sess)
                self.assertNotIn("username", sess)
            record_event.assert_called_once_with("LOGOUT", "alice", "SUCCESS")
        finally:
            response.close()

    def test_logout_without_username_still_clears_session(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 7
        response = self.post_data("/logout", {})
        try:
            self.assertEqual(response.status_code, 302)
            with self.client.session_transaction() as sess:
                self.assertNotIn("user_id", sess)
        finally:
            response.close()

    def test_security_demo_database_failure_returns_503(self):
        with patch.object(
            cipher_app, "fetch_one", side_effect=RuntimeError("database unavailable")
        ):
            response = self.post_data("/security-demo/test", {"sample": "payload" * 30})
        try:
            self.assertEqual(response.status_code, 503)
            self.assertIn(b"Security", response.data)
        finally:
            response.close()

    def test_security_demo_truncates_input_to_120_characters(self):
        payload = "x" * 150
        with patch.object(
            cipher_app, "fetch_one", return_value={"user_count": 2}
        ) as fetch:
            response = self.post_data("/security-demo/test", {"sample": payload})
        try:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(fetch.call_args.args[1][0]), 120)
        finally:
            response.close()

    def test_security_center_requires_login(self):
        response = self.client.get("/security-center")
        self.assertEqual(response.status_code, 302)
        response.close()

    def test_robots_and_sitemap_with_configured_base_url(self):
        with patch.dict(os.environ, {"APP_BASE_URL": "https://example.test"}):
            robots = self.client.get("/robots.txt")
            sitemap = self.client.get("/sitemap.xml")
        try:
            self.assertEqual(robots.status_code, 200)
            self.assertIn(b"Sitemap: https://example.test/sitemap.xml", robots.data)
            self.assertEqual(sitemap.status_code, 200)
            self.assertIn(b"https://example.test/security-demo", sitemap.data)
            self.assertEqual(sitemap.mimetype, "application/xml")
        finally:
            robots.close()
            sitemap.close()

    def test_sitemap_without_base_url_returns_503(self):
        with patch.dict(os.environ, {"APP_BASE_URL": ""}):
            response = self.client.get("/sitemap.xml")
        try:
            self.assertEqual(response.status_code, 503)
            self.assertIn(b"APP_BASE_URL is not configured", response.data)
        finally:
            response.close()

    def test_error_handlers_return_explicit_status_codes(self):
        with cipher_app.app.test_request_context("/missing"):
            not_found = cipher_app.not_found(Exception("missing"))
            too_large = cipher_app.request_too_large(Exception("large"))
            server_error = cipher_app.server_error(Exception("server"))
        self.assertEqual(not_found.status_code, 404)
        self.assertEqual(too_large.status_code, 413)
        self.assertEqual(server_error.status_code, 500)
        not_found.close()
        too_large.close()
        server_error.close()

    def test_request_too_large_route_returns_413(self):
        original_limit = cipher_app.app.config["MAX_CONTENT_LENGTH"]
        cipher_app.app.config["MAX_CONTENT_LENGTH"] = 10
        try:
            response = self.client.post(
                "/login",
                data={"username": "a" * 100, "password": "b" * 100},
            )
            self.assertEqual(response.status_code, 413)
            response.close()
        finally:
            cipher_app.app.config["MAX_CONTENT_LENGTH"] = original_limit


if __name__ == "__main__":
    unittest.main()
