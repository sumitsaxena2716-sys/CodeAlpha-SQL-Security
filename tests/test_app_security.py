"""Flask route/security regression tests; database operations are mocked."""

import unittest
from unittest.mock import patch

import app as cipher_app


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        cipher_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key-for-unit-tests-only",
        )
        self.client = cipher_app.app.test_client()

    def _csrf(self, path="/login"):
        self.client.get(path)
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
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            response.close()

    def test_missing_csrf_rejected(self):
        response = self.client.post(
            "/login",
            data={"username": "test", "password": "wrong"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Security validation failed", response.data)
        response.close()

    def test_invalid_csrf_rejected(self):
        self._csrf()
        response = self.client.post(
            "/login",
            data={
                "csrf_token": "invalid",
                "username": "test",
                "password": "wrong",
            },
        )
        self.assertEqual(response.status_code, 400)
        response.close()

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers["Location"])
        response.close()

    def test_custom_404_and_security_headers(self):
        response = self.client.get("/route-that-does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Return home", response.data)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("Content-Security-Policy", response.headers)
        response.close()

    def test_favicon_and_robots_available(self):
        favicon_response = self.client.get("/static/favicon.svg")
        try:
            self.assertEqual(favicon_response.status_code, 200)
        finally:
            favicon_response.close()

        robots_response = self.client.get("/robots.txt")
        try:
            self.assertEqual(robots_response.status_code, 200)
        finally:
            robots_response.close()

    def test_login_uses_parameterized_lookup(self):
        token = self._csrf()

        with patch.object(
            cipher_app, "fetch_one", return_value=None
        ) as fetch, patch.object(cipher_app, "record_event"):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "username": "tester",
                    "password": "not-correct",
                },
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
                data={
                    "csrf_token": token,
                    "sample": payload,
                },
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
            "/security-demo/test",
            data={"sample": "' OR '1'='1"},
        )

        try:
            self.assertEqual(response.status_code, 400)
        finally:
            response.close()

    def test_security_center_only_queries_current_user_events(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 10
            sess["username"] = "alice"
            sess["csrf_token"] = "test-csrf"

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
            "/security-demo/test",
            data={"sample": "' OR '1'='1"},
        )

        try:
            self.assertEqual(response.status_code, 400)
        finally:
            response.close()


if __name__ == "__main__":
    unittest.main()
